"""The shipper and the collector agree on a set of log classes, or logs vanish.

The shipper tags every event with a class name and the pipeline routes on it. A
class added on one side and not the other does not fail loudly: filebeat ships
happily, logstash has no filter for it, and the events land unparsed in an index
nobody built a view over. So the two lists are pinned to each other here.

The model is RedELK's, which keeps redirector traffic separate from teamserver
operations because they answer different questions -- "is my infrastructure being
used" and "is someone investigating it" -- and one index makes every query filter
before it can begin.
"""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
COLLECTOR = ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.collector"
SHIPPER = ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.shipper"

PIPELINE = (COLLECTOR / "templates/logstash-redstackpro.conf.j2").read_text(encoding="utf-8")
SHIPPER_DEFAULTS = yaml.safe_load((SHIPPER / "defaults/main.yml").read_text(encoding="utf-8"))


def _shipped_classes():
    return {c["name"] for c in SHIPPER_DEFAULTS["redstackpro_shipper_classes"]}


def test_every_shipped_class_has_a_filter():
    """A class with no filter indexes raw lines: no fields, no chart, no alarm.

    c2 was exempted here for as long as it had no parser, which made this test
    pass while one of three classes was landing raw. The exemption is gone.
    """
    for name in _shipped_classes():
        assert '[redstackpro][log_type] == "%s"' % name in PIPELINE, (
            "the shipper sends %r but the pipeline has no filter for it" % name)


def test_the_redirector_format_and_the_grok_carry_the_same_fields():
    """The two fields that make a redirector log worth indexing are added by the
    server config and read by the grok. Either side changing alone leaves the
    other parsing a shape that no longer arrives.
    """
    apache = (COLLECTOR.parent / "redstackpro.redirector/templates/apache-redirector.conf.j2"
              ).read_text(encoding="utf-8")
    nginx = (COLLECTOR.parent / "redstackpro.redirector/templates/nginx-redirector.conf.j2"
             ).read_text(encoding="utf-8")
    for field in ("rsp_gate=", "rsp_backend=", "rsp_host="):
        assert field in apache, "apache log format lost %s" % field
        assert field in nginx, "nginx log format lost %s" % field
        assert field in PIPELINE, "the grok no longer reads %s" % field


def test_a_callback_is_a_gated_request_that_reached_a_backend():
    """Callbacks are derived rather than shipped, so the derivation is the
    definition and belongs under test. A request that presented the key AND named
    a backend reached a teamserver; that is a beacon by construction, and it needs
    no per-C2 log parser to see.
    """
    assert 'clones => ["callback"]' in PIPELINE
    assert 'redstackpro-callbacks-' in PIPELINE
    # Cloned, not moved: the traffic index must still hold the request, or the
    # total-traffic view silently under-counts exactly the successful callbacks.
    body = PIPELINE[PIPELINE.index("clone {"):]
    assert "mutate" not in body.split("}")[0], "clone must not strip the original"


def test_a_wrong_key_is_tagged_because_it_means_someone_is_looking():
    """The reason the gate is logged as PRESENTED rather than as a boolean. A
    wrong token means the sender found a path that is linked from nowhere, which
    is the closest thing a redirector sees to being investigated. RedELK calls
    this class of query a bluecheck.
    """
    assert "rsp_bad_key" in PIPELINE
    assert '[redstackpro][gate] == "presented"' in PIPELINE


def test_each_class_lands_in_its_own_index():
    """Separate indices are the point: they chart, retain and permission
    differently. One index for everything would make each of those a query."""
    assert "redstackpro-%{[redstackpro][log_type]}-" in PIPELINE
    assert "redstackpro-callbacks-" in PIPELINE


def test_the_journal_covers_the_c2s_that_write_no_files():
    """Checked live 2026-09-13: sliver writes files, adaptix logs only to the
    journal, mythic runs in containers whose output docker forwards there. A
    file-path list alone would collect one C2 of three and look complete.
    """
    template = (SHIPPER / "templates/filebeat.yml.j2").read_text(encoding="utf-8")
    assert "type: journald" in template
    matches = [m for j in SHIPPER_DEFAULTS["redstackpro_shipper_journals"]
               for m in j["matches"] if j["name"] == "c2"]
    assert any("adaptix.service" in m for m in matches),         "adaptix has no log file; without the journal it is invisible"
    assert any("mythic" in m for m in matches),         "mythic runs in containers; its output reaches the journal"


def test_auth_keeps_only_the_lines_that_say_someone_got_in():
    """auth.log is mostly session bookkeeping. Indexing all of it buries the
    logins it exists to show."""
    assert re.search(r"Accepted ", PIPELINE)
    assert re.search(r"Failed ", PIPELINE)
    assert "drop {" in PIPELINE, "everything that is not an auth decision should be dropped"


DASHBOARD = (COLLECTOR / "templates/dashboard-objects.ndjson.j2").read_text(encoding="utf-8")

def _index_template():
    """The index template, RENDERED.

    It is a .j2 and must be treated as one. These tests used to json.loads the
    file directly, which worked only for as long as the template happened to
    contain no Jinja -- the moment a comment was added to explain a mapping
    choice, three tests failed on the template rather than on anything they were
    testing.
    """
    import json as _json
    from jinja2 import Environment
    raw = (COLLECTOR / "templates/index-template.json.j2").read_text(encoding="utf-8")
    return _json.loads(Environment().from_string(raw).render())



def test_the_dashboard_covers_what_the_pipeline_produces():
    """A panel over an index nothing writes is worse than no panel: it reads as a
    broken product rather than a missing feature. So every index pattern in the
    saved objects must be one the pipeline actually fills.
    """
    import json
    objects = [json.loads(line) for line in DASHBOARD.strip().splitlines()]
    patterns = {o["attributes"]["title"] for o in objects if o["type"] == "index-pattern"}
    assert patterns == {
        "redstackpro-redirtraffic-*", "redstackpro-callbacks-*",
        "redstackpro-auth-*", "redstackpro-c2-*"}
    # callbacks is written by its own output block; the rest come from the
    # log_type interpolation.
    assert "redstackpro-callbacks-" in PIPELINE
    assert "redstackpro-%{[redstackpro][log_type]}-" in PIPELINE


def test_no_panel_points_at_an_object_that_is_not_there():
    """An import that half resolves leaves panels referencing index patterns that
    do not exist, which is exactly how a dashboard looks broken on first login.
    """
    import json
    objects = [json.loads(line) for line in DASHBOARD.strip().splitlines()]
    known = {o["id"] for o in objects}
    for o in objects:
        for ref in o.get("references", []):
            assert ref["id"] in known, (
                "%s references %s, which the import does not create"
                % (o["id"], ref["id"]))


def test_the_dashboard_shows_the_signal_worth_alarming_on():
    """The bad-key panel is the point of logging the gate as presented rather
    than as a boolean: a wrong token means the sender found a path that is linked
    from nowhere. Without the panel the field is just stored."""
    assert "rsp_bad_key" in DASHBOARD
    assert "rsp_bad_key" in PIPELINE


def test_the_portal_only_offers_the_dashboard_when_there_is_a_collector():
    """A range with no collector must not grow a /dashboards link that proxies
    nowhere; the location is emitted only when the address is known."""
    portal = (COLLECTOR.parent / "redstackpro.jumpbox/templates/guacamole-nginx.conf.j2"
              ).read_text(encoding="utf-8")
    assert "redstackpro_collector_address | default('') | length > 0" in portal
    assert "/dashboards/" in portal


def test_the_dashboard_is_reached_through_the_portal_not_a_new_public_port():
    """The range's public surface stays 443 and 22.
    The dashboard is proxied from the portal the operator already opens, and the
    collector itself holds no public address."""
    cfg = (COLLECTOR / "templates/opensearch-dashboards.yml.j2").read_text(encoding="utf-8")
    # basePath must agree with the portal's location block or every asset 404s.
    assert 'server.basePath: "/dashboards"' in cfg
    assert "server.rewriteBasePath: true" in cfg


def test_the_portal_is_a_login_source_not_just_sshd():
    """Guacamole IS the operator's front door -- sshd never sees a portal login,
    so an auth index fed only by auth.log misses the logins that matter most.
    The portal is a container logging in Java's shape, not syslog's, so it needs
    its own pattern and its own journald input.
    """
    template = (SHIPPER / "templates/filebeat.yml.j2").read_text(encoding="utf-8")
    journals = SHIPPER_DEFAULTS["redstackpro_shipper_journals"]
    portal = [j for j in journals if j["name"] == "auth"]
    assert portal, "nothing ships portal logins into the auth class"
    assert any("redstackpro-guacamole" in m for j in portal for m in j["matches"])
    assert "successfully authenticated" in PIPELINE
    assert "_portal_unparsed" in PIPELINE


def test_each_journal_input_keeps_to_one_match_field():
    """journald ORs matches on the same field and ANDs them across fields, so an
    input mixing _SYSTEMD_UNIT with CONTAINER_NAME asks for entries that are both
    and matches nothing at all. Verified against the filebeat 8.15 docs.
    """
    for j in SHIPPER_DEFAULTS["redstackpro_shipper_journals"]:
        fields = {m.split("=", 1)[0] for m in j["matches"]}
        assert len(fields) == 1, (
            "journal input %r mixes %s; different fields are ANDed and it will "
            "match nothing" % (j["id"], sorted(fields)))


def test_an_unrecognised_auth_line_is_kept_rather_than_dropped():
    """A silent drop is how you find out months later that a whole source was
    never indexed. Lines that match no pattern arrive tagged instead, and the tag
    going quiet is the signal that the patterns are right."""
    assert "rsp_auth_unrecognised" in PIPELINE
    # The drop stays, but only for lines that DID parse as syslog and simply
    # said nothing about an authentication decision.
    drop_guard = PIPELINE[:PIPELINE.index("drop { }")]
    assert "else if [redstackpro][detail] {" in drop_guard


def test_the_jumpbox_ships_without_an_edge_it_cannot_have():
    """The collector's receiver certificate is issued by the jumpbox's own
    authority, so a logs_to edge from the jumpbox is a dependency cycle the
    generator refuses. It falls back to the collector address instead -- and to
    the collector's PORT and TLS choice, because two defaults that agree today
    drift the moment someone edits the overlay.
    """
    defaults = SHIPPER_DEFAULTS
    assert "redstackpro_collector_address" in str(defaults["redstackpro_shipper_sink"])
    assert "redstackpro_collector_ingest_port" in str(defaults["redstackpro_shipper_port"])
    assert "redstackpro_collector_tls" in str(defaults["redstackpro_shipper_tls"])


def test_an_unparsed_line_is_not_mistaken_for_a_callback():
    """A field can be absent because it held the "-" sentinel, or because the
    grok never matched. Both must land in the same branch.

    The first version tested only the sentinel, so an unparsed line fell to the
    else and was labelled proxied. A live range proved it within minutes: a
    scanner probing /%2e%2e%2f%2eenv from Amsterdam was cloned into the callbacks
    index as a beacon reaching a teamserver. A dashboard that counts scans as
    callbacks is worse than one with no data at all.
    """
    assert "![redstackpro][gate_presented] or" in PIPELINE
    assert "![redstackpro][backend] or" in PIPELINE


def test_a_callback_needs_both_the_key_and_a_backend():
    """Either alone is something else: a wrong key that reached nothing is a
    probe, and a backend with no key cannot happen through the gate."""
    assert ('[redstackpro][proxied] == "true" and [redstackpro][gate] == "presented"'
            in PIPELINE)


def test_geoip_writes_ecs_paths_not_a_doubled_one():
    """geoip adds its own `geo` object under whatever target it is given, so a
    target of [source][geo] produces source.geo.geo.country_name. ECS says
    source.geo.*, which is what the dashboard queries -- the panel was silently
    empty on a live range until a field listing showed the doubled path.
    """
    assert 'target => "[source][geo]"' not in PIPELINE, (
        "geoip target is doubled again; fields land at source.geo.geo.* and "
        "every panel that reads source.geo.* goes quiet")
    assert PIPELINE.count('target => "[source]"') >= 2, (
        "both the redirtraffic and auth geoip filters should target [source]")
    # The dashboard's own query has to agree with what the pipeline writes.
    assert "source.geo.country_name" in DASHBOARD


def test_the_indices_are_typed_before_a_document_creates_them():
    """Dynamic mapping makes every string a text field, and a text field cannot
    be aggregated -- "Text fields are not optimised for operations that require
    per-document field data". Every panel on the dashboard aggregates, so all
    five would have shown an error instead of data.

    Proven on a live index before the template existed: node_id, backend,
    country_name, user_agent.name, source.ip and url.original ALL failed. A
    field's mapping is fixed when the index is created, so the template has to be
    in place before the first document arrives -- hence before the pipeline is
    written, not after.
    """
    tpl = _index_template()
    assert tpl["index_patterns"] == ["redstackpro-*"]

    props = tpl["template"]["mappings"]["properties"]
    # The identifiers every panel groups by.
    for field in ("node_id", "backend", "gate", "log_type", "uri_prefix"):
        assert props["redstackpro"]["properties"][field]["type"] == "keyword"
    # Real types where they earn something: a CIDR query on an address, a map on
    # the geo point.
    assert props["source"]["properties"]["ip"]["type"] == "ip"
    assert props["source"]["properties"]["geo"]["properties"]["location"]["type"] == "geo_point"
    # Anything not named still aggregates, rather than silently becoming text.
    dyn = tpl["template"]["mappings"]["dynamic_templates"][0]
    assert dyn["strings_are_keywords"]["mapping"]["type"] == "keyword"

    receiver = (COLLECTOR / "tasks/receiver.yml").read_text(encoding="utf-8")
    assert receiver.index("_index_template") < receiver.index("Write the pipeline"), (
        "the template must be applied before the pipeline can create an index")


def test_the_dashboard_groups_by_fields_the_template_makes_keyword():
    """With the template in place the fields ARE keyword, so a .keyword subfield
    does not exist. A panel asking for one aggregates nothing and shows an empty
    table, which reads as "no traffic" rather than "wrong field name".
    """
    assert ".keyword" not in DASHBOARD, (
        "a panel references a .keyword subfield; the index template maps these "
        "as keyword directly, so that subfield is not there")


def test_the_index_patterns_are_given_their_fields():
    """An imported index pattern carries no field list, and Dashboards does NOT
    fetch one when a panel first renders. Every visualisation then fails with
    "Trying to initialize aggs without index pattern": five empty boxes, each
    with an error, over data that is perfectly fine.

    Invisible to every check made through the API -- indices had documents,
    fields aggregated, saved objects imported, the port answered 200. It took a
    screenshot of the actual page to see it, which is the whole argument for
    looking at the thing a person looks at.
    """
    tasks = (COLLECTOR / "tasks/dashboards.yml").read_text(encoding="utf-8")
    assert "_fields_for_wildcard" in tasks, (
        "nothing populates the index pattern field lists; the dashboard will "
        "render five errors")
    # After the import, because the objects have to exist to be updated.
    assert tasks.index("Import the redStackPRO dashboard") < tasks.index("field list")
    # And asserted, because an empty list looks exactly like a working deploy
    # until someone opens the page.
    assert "Confirm the patterns actually carry fields" in tasks


# --------------------------------------------------------------- teamserver logs
#
# The c2 class shipped for months with no filter behind it, so every teamserver
# line landed in redstackpro-c2-* as a raw message with filebeat's read time on
# it. These pin the parser that closed that, and the facts about the products it
# reads, each of which was checked against the upstream source rather than
# assumed from the shape of a line.


def _c2_sources():
    """Every c2 input, files and journals alike."""
    return ([c for c in SHIPPER_DEFAULTS["redstackpro_shipper_classes"] if c["name"] == "c2"]
            + [j for j in SHIPPER_DEFAULTS["redstackpro_shipper_journals"] if j["name"] == "c2"])


def test_sliver_ships_the_machine_readable_log_not_the_colouart_one():
    """Sliver's root logger is a logrus JSONFormatter onto sliver.json, and a hook
    renders THE SAME events as text onto sliver.log with ForceColors set. The glob
    here was *.log, which took the copy carrying ANSI escapes, missed the JSON,
    and left the class unparseable while gaining nothing -- the two files hold the
    same events.
    """
    # `or []`, not a default: an entry whose paths key is present but EMPTY
    # parses as None, and indexing that raises TypeError, which reads as a broken
    # test rather than as a missing log source.
    paths = [p for c in _c2_sources() for p in (c.get("paths") or [])]
    assert any(p.endswith("/sliver.json") for p in paths), (
        "sliver.json is the structured copy; without it the class needs a grok "
        "for a format that is already JSON next door")
    assert not any(p.endswith("/sliver.log") or p.endswith("/*.log") for p in paths), (
        "sliver.log duplicates sliver.json and carries ANSI colour escapes")


def test_the_audit_log_is_the_only_per_implant_source_and_is_shipped():
    """audit.json is what the derived callbacks index cannot be. A callback comes
    from the redirector, so it can only say which teamserver answered; sliver's
    audit entries name the operator, the RPC method, and the session or beacon.
    """
    paths = [p for c in _c2_sources() for p in (c.get("paths") or [])]
    assert any(p.endswith("/audit.json") for p in paths), (
        "nothing ships sliver's audit log, so no index can say which implant")


def test_the_audit_payload_is_decoded_twice_because_it_is_doubly_encoded():
    """Sliver marshals its audit struct to JSON and passes the RESULT AS A STRING
    to the logger, so the fields sit inside logrus's own msg rather than beside
    it. One json filter yields a document whose only interesting field is a blob.

    Verified against server/transport/middleware.go: `msgData, _ := json.Marshal(msg)`
    then `log.AuditLogger.Info(string(msgData))`.
    """
    assert 'source => "message"' in PIPELINE
    assert 'source => "[rsp_logrus][msg]"' in PIPELINE, (
        "the audit fields are nested inside logrus's msg; decoding the envelope "
        "alone leaves session, beacon and user unparsed")
    # And the fields that make it worth doing at all.
    for field in ("[user][name]", "[redstackpro][c2][method]",
                  "[redstackpro][c2][session]", "[redstackpro][c2][beacon]"):
        assert field in PIPELINE, "the audit mapping dropped %s" % field


def test_sliver_remote_ip_is_split_before_it_reaches_an_ip_field():
    """remote_ip is a Go net.Addr, so it is host:port -- "127.0.0.1:54962".

    source.ip is mapped as type ip, and renaming the raw value across made
    OpenSearch reject the WHOLE document: mapper_parsing_exception, status 400,
    every audit event discarded. The operator, the method and the session were
    all parsed correctly and thrown away with it, so the one thing this branch
    exists to produce never reached the index.

    Caught on a live range 2026-09-18 and invisible before it: the field is
    named remote_ip, every sample looked like an address, and only a real
    teamserver writing into a real strict mapping showed the port glued on.
    """
    branch = PIPELINE[PIPELINE.index("---- sliver"):PIPELINE.index("---- adaptix")]
    pairs = re.findall(r'"(\[rsp_audit\][^"]+)"\s*=>\s*"([^"]+)"', branch)
    for src, dst in pairs:
        assert not (src.endswith("[remote_ip]") and dst == "[source][ip]"), (
            "remote_ip is renamed straight into an ip-typed field; a host:port "
            "value rejects the entire event")
    assert "[rsp_audit][remote_ip]" in branch, "remote_ip is not read at all"
    assert "[source][port]" in branch, "the port half is thrown away"


def test_a_bad_value_costs_a_field_rather_than_the_whole_event():
    """The second line of defence behind the split above.

    A strictly typed field can discard an entire document, and that is a poor
    trade in a log pipeline: an event with one unparseable address is still
    worth having. ignore_malformed keeps the event and drops the field.
    """
    tpl = _index_template()
    source = tpl["template"]["mappings"]["properties"]["source"]["properties"]
    assert source["ip"].get("ignore_malformed") is True, (
        "one malformed address can still throw away a whole event")
    assert source["port"].get("ignore_malformed") is True
    # And the note explaining why must not leak in as a mapping field.
    assert not [k for k in source if k.startswith("_comment")], (
        "a comment key inside properties is read as a field with an invalid mapping")


def test_session_and_beacon_collapse_into_one_implant_field():
    """They are the same question asked of two transports and sliver sets
    whichever applies, so a panel that had to know which would show half the
    picture."""
    assert "[redstackpro][c2][implant]" in PIPELINE
    body = PIPELINE[PIPELINE.index("[redstackpro][c2][implant]") - 400:]
    assert "session" in body and "beacon" in body


def test_the_c2_timestamp_is_the_events_own_not_the_shippers():
    """Without a date filter every c2 document is stamped when filebeat caught
    up, which makes activity-over-time a chart of the shipper."""
    assert '"[rsp_logrus][time]", "ISO8601"' in PIPELINE, (
        "c2 events keep filebeat's read time; the one chart anybody wants is "
        "then a chart of the shipper rather than of the teamserver")


def test_every_c2_source_says_which_product_wrote_it():
    """Four products write four unrelated shapes into one class, so the branch
    cannot route on the class alone. The shipper stamps it at the one place that
    knows for certain, rather than the collector sniffing it off the line.
    """
    for src in _c2_sources():
        assert src.get("product"), (
            "c2 source %r carries no product stamp, so the pipeline has nothing "
            "to route it on and it lands unparsed" % src.get("id", src))


def test_both_sliver_units_are_collected():
    """The role installs sliver.service AND sliver-listener.service, and tells the
    operator to read `journalctl -u sliver-listener` when a listener misbehaves.
    Only the first was collected, so a listener failing to bind was invisible
    while the teamserver unit looked healthy.
    """
    matches = [m for j in SHIPPER_DEFAULTS["redstackpro_shipper_journals"]
               for m in j["matches"] if j["name"] == "c2"]
    assert any("sliver-listener.service" in m for m in matches), (
        "the listener unit is not collected; a failed listener is silent")


def test_an_unstamped_c2_event_is_kept_and_tagged_rather_than_dropped():
    """Same rule as the auth class: a silent drop is how a whole source turns out
    to have been missing for months."""
    assert "rsp_c2_unstamped" in PIPELINE
    # The whole branch, not a window around the tag: a `drop` anywhere in it
    # loses c2 events, and the first version of this test matched the word in a
    # COMMENT rather than in a filter, which is a test of the prose.
    branch = PIPELINE[PIPELINE.index('if [redstackpro][log_type] == "c2" {'):
                      PIPELINE.index("output {")]
    assert "drop {" not in branch, "the c2 branch drops events instead of tagging them"
    assert "rsp_c2_unstamped" in branch


def test_the_dashboard_finally_points_at_the_c2_index():
    """rsp-c2 existed as an index pattern from the first dashboard and nothing
    referenced it, so teamserver activity was Discover-only: the data arrived and
    the product never showed it.
    """
    import json
    objects = [json.loads(line) for line in DASHBOARD.strip().splitlines()]
    users = [o for o in objects if o["type"] == "visualization"
             and any(r["id"] == "rsp-c2" for r in o.get("references", []))]
    assert users, "no visualisation reads redstackpro-c2-*"
    # And the dashboard has to actually show them, not just define them.
    dash = next(o for o in objects if o["id"] == "rsp-dashboard")
    shown = {r["id"] for r in dash["references"]}
    for viz in users:
        assert viz["id"] in shown, (
            "%s reads the c2 index but is on no dashboard" % viz["id"])


def test_the_two_ansi_sources_are_stripped_before_they_are_grokked():
    """adaptix colours its output, and mythic_server runs zerolog's ConsoleWriter
    with NoColor left at its zero value, so both arrive with escapes in them. A
    grok anchored on '[' meets an escape sequence first and matches nothing.
    """
    # The JOURNAL branches specifically. Both products now have a second,
    # structured branch (a JSON export and a logging container) that has no
    # escapes in it, and slicing from the first mention of the product lands on
    # that one instead.
    for label, head, tail in (
            ("adaptix", "---- adaptix, the journal", "---- mythic, the server container"),
            ("mythic", "---- mythic, the server container", "---- mythic, the logging")):
        branch = PIPELINE[PIPELINE.index(head):PIPELINE.index(tail)]
        assert "gsub" in branch, (
            "%s's console output is colourised and is never stripped" % label)


def test_the_template_carries_no_raw_control_bytes():
    """The ANSI strip has to name an escape character, and writing it as a literal
    puts an invisible 0x1B in a generated config: it survives no copy-paste, shows
    as nothing in a diff, and cannot be reviewed. \\p{Cntrl} says the same thing in
    printable characters.

    This happened: the first version of the strip wrote the byte itself.
    """
    for path in ((COLLECTOR / "templates/logstash-redstackpro.conf.j2"),
                 (SHIPPER / "templates/filebeat.yml.j2")):
        raw = path.read_bytes()
        bad = {b for b in raw if b < 9 or 13 < b < 32}
        assert not bad, "%s holds raw control bytes %s" % (path.name, sorted(bad))


def test_the_mythic_server_stream_is_parsed_for_health_only():
    """mythic_server carries no operator and no callback id on any code path --
    its fields are func, line and error. Anything claiming to extract a callback
    from THAT stream is inventing fields.

    Scoped to the unit stream. The logging container is a different stream on the
    same product and does carry both, which is the whole reason it is deployed;
    this test used to cover the product as a whole and would have forbidden it.
    """
    start = PIPELINE.index('[redstackpro][c2][product] == "mythic" and '
                           '[redstackpro][c2][stream] == "unit"')
    branch = PIPELINE[start:PIPELINE.index("mythic, the logging container")]
    for invented in ("callback_id", "operator_username", "[user][name]"):
        assert invented not in branch, (
            "the mythic server branch claims to read %s, which its stdout does "
            "not carry" % invented)


def test_the_mythic_logging_container_is_what_supplies_the_attribution():
    """The server container is health. The logging container subscribes to
    Mythic's RabbitMQ stream and is the only place an operator and a callback id
    appear, so it has to be installed as well as parsed -- a branch reading a
    stream nothing produces is worse than no branch.
    """
    path = (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.teamserver"
            "/tasks/c2-mythic.yml")
    tasks = yaml.safe_load(path.read_text(encoding="utf-8"))
    install = [t for t in tasks
               if "basic_logger" in str(t.get("ansible.builtin.command", {}).get("cmd", ""))
               and "install" in str(t["ansible.builtin.command"]["cmd"])]
    assert install, "nothing installs a Mythic logging container"

    # The PARSED command, not the text of the task: the comment inside it
    # explains why -f and timeout are there, so a substring search over the
    # block matches the prose and passes even when the command has neither.
    # That is exactly what the first version of this test did.
    cmd = install[0]["ansible.builtin.command"]
    assert " -f" in cmd["cmd"], "the logger install can prompt and then hang"
    assert cmd.get("stdin") == "", "no empty stdin, so an unexpected prompt blocks"
    assert "timeout " in cmd["cmd"], "an unbounded install can wedge the play"

    # And the shipper has to actually collect it.
    events = [j for j in SHIPPER_DEFAULTS["redstackpro_shipper_journals"]
              if j.get("product") == "mythic" and j.get("stream") == "events"]
    assert events, "nothing ships the logging container's output"
    assert any("basic_logger" in m for j in events for m in j["matches"])


def test_the_adaptix_export_is_deployed_and_collected():
    """A branch that parses a file nothing writes is worse than no branch: the
    index stays empty and looks like a quiet teamserver. Adaptix records its
    operator and agent only in SQLite, so the exporter is the whole source."""
    adaptix = (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.teamserver"
               "/tasks/c2-adaptix.yml").read_text(encoding="utf-8")
    assert "rsp-adaptix-export" in adaptix, "nothing installs the exporter"
    assert "rsp-adaptix-export.timer" in adaptix, "the exporter is never scheduled"

    paths = [p for c in _c2_sources() for p in (c.get("paths") or [])]
    out = [p for p in paths if "adaptix" in p]
    assert out, "the exporter's output is not shipped"
    # The two halves have to name the same file or the export goes nowhere.
    for path in out:
        assert path in adaptix, (
            "the shipper reads %s and nothing writes it there" % path)


def test_the_exporter_never_writes_to_the_database_it_reads():
    """Adaptix is writing to that file while this reads it. A reader able to take
    a write lock is a tool that can wedge the teamserver it is watching."""
    src = (ROOT / "src/redstackpro/assets/ansible/roles/redstackpro.teamserver"
           "/files/rsp-adaptix-export.py").read_text(encoding="utf-8")
    assert "mode=ro" in src and "uri=True" in src


def test_every_container_the_shipper_reads_sends_its_output_to_the_journal():
    """A CONTAINER_NAME match is a journald match, and Debian's docker defaults
    to the json-file driver, which writes under /var/lib/docker and nowhere
    else. So every container-sourced class silently collected nothing.

    Measured on a live range 2026-09-18: the c2 index held 292 documents, of
    which sliver 260 and adaptix 32 and mythic ZERO; the auth index held 324 and
    not one was a portal login, though Guacamole IS the operator's front door
    and sshd never sees those logins. Both indices looked healthy, because the
    file-based sources filled them.

    The driver must also be set BEFORE any container is created: it is fixed at
    creation, so configuring it afterwards and restarting leaves existing
    containers on the old driver.
    """
    import yaml as _yaml
    roles = ROOT / "src/redstackpro/assets/ansible/roles"
    # Where the shipper expects container output, and the file that installs
    # docker for it.
    sources = {
        "redstackpro-guacamole": roles / "redstackpro.jumpbox/tasks/service-guacamole.yml",
        "mythic_server": roles / "redstackpro.teamserver/tasks/c2-mythic.yml",
    }
    watched = {m.split("=", 1)[1]
               for j in SHIPPER_DEFAULTS["redstackpro_shipper_journals"]
               for m in j["matches"] if m.startswith("CONTAINER_NAME=")}
    assert watched, "nothing collects container output at all"

    for container, path in sources.items():
        assert container in watched, (
            "%s is no longer collected; drop it from this test or from the "
            "shipper" % container)
        text = path.read_text(encoding="utf-8")
        assert '"log-driver": "journald"' in text, (
            "%s installs docker but never points it at the journal, so every "
            "CONTAINER_NAME match against it collects nothing" % path.name)

        tasks = _yaml.safe_load(text)

        # Located by what the task DOES -- writes /etc/docker/daemon.json -- not
        # by its name. Matching the name found the task even after a mutation
        # renamed and moved it, so the ordering check below passed over exactly
        # the regression it exists to catch.
        driver = next(
            (i for i, t in enumerate(tasks)
             if str(t.get("ansible.builtin.copy", {}).get("dest", "")) ==
             "/etc/docker/daemon.json"), None)
        assert driver is not None, (
            "%s never writes /etc/docker/daemon.json" % path.name)

        # Anything that brings a container up must come after it.
        #
        # Matched on the MODULE a task uses, plus the one command that starts
        # containers, rather than on a substring of the whole task. A substring
        # search matched "docker_compose" inside the variable name
        # redstackpro_docker_compose_version, in a task that installs the compose
        # plugin and creates nothing -- a false failure of exactly the kind this
        # file fixed in verify.py the same afternoon.
        def creates_a_container(task):
            if any(k.endswith(("docker_container", "docker_compose",
                               "docker_compose_v2")) for k in task):
                return True
            cmd = str(task.get("ansible.builtin.command", {}).get("cmd", ""))
            return "mythic-cli start" in cmd

        for i, task in enumerate(tasks):
            if creates_a_container(task):
                assert i > driver, (
                    "%s creates a container at task %d but sets the log driver "
                    "at %d; the driver is fixed at CREATION, so those "
                    "containers keep the old one"
                    % (path.name, i, driver))
    """They are different formats on the same product: the server prints
    colourised text, the logging container prints JSON. journald would happily OR
    two CONTAINER_NAME matches into one input, and the result would stamp the
    JSON with stream: unit and route it into the health grok, which parses none
    of it.
    """
    for j in SHIPPER_DEFAULTS["redstackpro_shipper_journals"]:
        if j.get("product") != "mythic":
            continue
        names = {m.split("=", 1)[1] for m in j["matches"]}
        assert not ({"mythic_server"} & names and
                    {"basic_logger", "mythic_basic_logger"} & names), (
            "input %r mixes the server container with the logging container"
            % j["id"])


def test_implant_crypto_keys_are_never_indexed():
    """A new_callback payload carries the implant's dec_key and enc_key. Indexing
    those would put live implant crypto in the log store, searchable by anyone
    who can open the dashboard and retained as long as the index is.
    """
    branch = PIPELINE[PIPELINE.index("mythic, the logging container"):]
    branch = branch[:branch.index("cobalt strike")]
    for key in ("dec_key", "enc_key"):
        assert key in branch, "%s is not removed from the mythic event" % key
    removed = branch[branch.index("remove_field"):]
    for key in ("dec_key", "enc_key"):
        assert key in removed, "%s is mentioned but not in a remove_field" % key


def test_a_mythic_task_can_join_the_callback_it_ran_against():
    """The join key has to be the same identifier on both event shapes. A task
    carries `callback_id`, which is a foreign key onto `callback.id` -- the
    database primary key, not `display_id`, which is the per-operation number the
    UI shows.

    Keying callbacks on their uuid or their display id instead would put one kind
    of identifier on one event and another on the other, and every task would be
    orphaned from its callback with nothing reporting a problem.
    """
    branch = PIPELINE[PIPELINE.index("mythic, the logging container"):]
    branch = branch[:branch.index("cobalt strike")]
    cb = branch[branch.index('== "new_callback"'):branch.index("} else {")]
    task = branch[branch.index("} else {"):branch.index("[event][kind]")]

    # The rename PAIRS, not the surrounding text: the comment above these lines
    # names agent_callback_id to explain why it is not the key, and a substring
    # search over the block reads that prose as code. Fourth time that shape of
    # mistake has been made in this file's tests.
    def key_source(block):
        pairs = re.findall(r'"(\[rsp_mythic\][^"]+)"\s*=>\s*"([^"]+)"', block)
        return next((src for src, dst in pairs
                     if dst == "[redstackpro][c2][implant]"), None)

    assert key_source(cb) == "[rsp_mythic][data][data][id]", (
        "callbacks are keyed on %r rather than callback.id, so no task can join "
        "them" % key_source(cb))
    assert key_source(task) == "[rsp_mythic][data][callback_id]", (
        "tasks are keyed on %r" % key_source(task))


def test_the_two_mythic_payload_shapes_are_handled_separately():
    """Upstream's callback handler logs the whole envelope and every other
    handler logs the bare payload, so a new_callback has its operator at
    data.username and its callback one level further down, while a new_task has
    its fields directly under data. Reading a task's operator from data.username
    finds nothing.
    """
    branch = PIPELINE[PIPELINE.index("mythic, the logging container"):]
    branch = branch[:branch.index("cobalt strike")]
    assert '[redstackpro][c2][event] == "new_callback"' in branch, (
        "the two payload shapes are not told apart")
    assert "[rsp_mythic][data][data][agent_callback_id]" in branch, (
        "the callback payload is read at the wrong depth")
    assert "[rsp_mythic][data][operator_username]" in branch, (
        "the task payload is read at the wrong depth")


def test_the_cobalt_strike_beacon_id_comes_off_the_path_not_the_line():
    """Its beacon logs put the session id in the FILENAME, beacon_<bid>.log, and
    nowhere in the body. A parser reading only the message can never say which
    implant a line belongs to.
    """
    assert "[log][file][path]" in PIPELINE, (
        "nothing reads the cobalt strike filename, so no line has an implant id")
    assert "beacon_" in PIPELINE


def test_only_cobalt_strikes_input_lines_are_read_for_an_operator():
    """The angle brackets on a [task] line hold MITRE technique ids -- the real
    logs show `[task] <T1113, T1093> Tasked beacon to take screenshot`. A pattern
    that read the brackets without checking the entry type would file ATT&CK
    numbers as the names of people.
    """
    branch = PIPELINE[PIPELINE.index('[redstackpro][c2][product] == "cobaltstrike"'):]
    assert '[redstackpro][c2][entry] == "input"' in branch, (
        "the operator grok is not gated on the entry type; [task] lines would "
        "yield MITRE ids as usernames")
    guard = branch.index('[redstackpro][c2][entry] == "input"')
    assert branch.index("[user][name]") > guard, (
        "the operator is read before the entry type is checked")


def test_cobalt_strike_records_that_span_lines_are_kept_whole():
    """An [output] record is a header line and then the output itself, so the
    default one-line-one-event turns every response into orphan fragments that
    carry no timestamp, no type and no beacon."""
    cs = [c for c in _c2_sources() if c.get("product") == "cobaltstrike"]
    assert cs, "cobalt strike ships nothing"
    for src in cs:
        assert src.get("multiline_pattern"), (
            "%s has no multiline pattern; [output] arrives in pieces" % src["id"])
    template = (SHIPPER / "templates/filebeat.yml.j2").read_text(encoding="utf-8")
    assert "multiline" in template and "negate: true" in template


def test_cobalt_strike_is_shipped_at_all():
    """The role installs a JRE and a README and the operator supplies the archive,
    so nothing here knows where it lands. Until these globs existed a Cobalt
    Strike teamserver shipped ZERO c2 events and looked exactly like a quiet one.
    """
    paths = [p for c in _c2_sources() for p in (c.get("paths") or [])]
    assert any("beacon_" in p for p in paths), "no cobalt strike beacon logs"
    assert any("events.log" in p for p in paths), "no cobalt strike events log"


def test_a_timestamp_is_reparsed_only_where_filebeats_own_is_wrong():
    """The rule is about the TRANSPORT, not the product.

    A journald source is stamped by journald with the real entry time, so
    re-deriving one can only make it worse -- and adaptix's printed time has no
    year and no zone, while cobalt strike's has no year either, so "worse" means
    every event in the wrong year.

    A FILE source is stamped when filebeat read it, which is not when the event
    happened. That gap is why sliver's files carry a date filter, and why the
    adaptix export does: it is written by a timer that runs every thirty
    seconds, so its read time can be half a minute after the operator typed the
    command. Its exporter has already resolved the epoch-unit ambiguity and
    emits ISO8601, so there is a trustworthy time to take.
    """
    branch = PIPELINE[PIPELINE.index('if [redstackpro][log_type] == "c2" {'):
                      PIPELINE.index("output {")]

    def section(head, tail):
        return branch[branch.index(head):branch.index(tail)]

    # File-backed, and each carries a date filter. Bounded by the section
    # headers exactly: "---- adaptix" alone also matches "---- adaptix, the
    # journal", so the sliver slice would swallow the export branch and pass on
    # ITS date filter rather than sliver's.
    # The FIELD each one reads, not merely that a date filter is present. A
    # filter pointed at a field the event does not carry is a no-op that leaves
    # filebeat's timestamp in place, and asserting only on "date {" passes over
    # exactly that.
    sliver = section("---- sliver", "---- adaptix, the task export")
    assert '"[rsp_logrus][time]", "ISO8601"' in sliver, (
        "sliver's files keep filebeat's read time")
    export = section("---- adaptix, the task export", "---- adaptix, the journal")
    assert '"[rsp_adx][started]", "ISO8601"' in export, (
        "the adaptix export keeps the poll time rather than the task time")

    # journald-backed, and none of them may re-derive.
    for label, head, tail in (
            ("adaptix journal", "---- adaptix, the journal", "---- mythic, the server"),
            ("mythic server", "---- mythic, the server", "---- mythic, the logging"),
            ("mythic events", "---- mythic, the logging", "---- cobalt strike"),
            ("cobalt strike", "---- cobalt strike", "The printed timestamp")):
        assert "date {" not in section(head, tail), (
            "%s re-parses a timestamp journald already got right" % label)


def test_the_products_that_only_yield_health_still_have_a_panel():
    """The first two c2 panels are both sliver-shaped: one reads the audit stream,
    the other the implant id. adaptix and mythic carry neither by their own
    design, so without a panel over product and level their branches would parse
    into fields nothing ever shows -- the same defect as an index pattern with no
    panel, one level further in.
    """
    assert "redstackpro.c2.product" in DASHBOARD, (
        "no panel groups by product, so adaptix and mythic parse into nothing")
    assert "log.level" in DASHBOARD, (
        "severity is the only signal those two emit and no panel shows it")


def test_the_c2_fields_are_typed_like_every_other_grouping_field():
    """A panel groups by these, and an untyped string becomes text, which cannot
    be aggregated. The dynamic template would catch them, but naming them is what
    stops a later mapping change from quietly making them text."""
    tpl = _index_template()
    c2 = tpl["template"]["mappings"]["properties"]["redstackpro"]["properties"]["c2"]
    for field in ("product", "stream", "method", "session", "beacon", "implant"):
        assert c2["properties"][field]["type"] == "keyword", (
            "redstackpro.c2.%s is not keyword; any panel grouping by it fails" % field)


def test_apt_can_verify_the_opensearch_repository_before_it_is_added():
    """The collector could not install at all on the default image, and the
    ordering is the whole fix.

    OpenSearch signs its apt repository with a key whose binding signature is
    SHA-1. Debian 13 verifies repository signatures with Sequoia's sqv, whose
    policy stopped accepting SHA-1 on 2026-02-01, so the repository reads as
    unsigned and apt refuses it. `apt_repository` runs its own update, so a
    policy written AFTER that task is written after the failure it exists to
    prevent -- the tasks would both be present, in the wrong order, and the
    deploy would fail exactly as it did before.

    Found on the first live deploy after Debian 13 became the default. Nothing
    offline caught it: the task is well formed, the key downloads, the URL is
    right, and every syntax and unit check passed.
    """
    tasks = yaml.safe_load(
        (COLLECTOR / "tasks/sink-opensearch.yml").read_text(encoding="utf-8"))
    names = [t.get("name", "") for t in tasks]

    policy = next(i for i, n in enumerate(names) if "SHA-1" in n)
    repo = next(i for i, n in enumerate(names) if "opensearch repository" in n)
    assert policy < repo, names

    written = tasks[policy]["ansible.builtin.copy"]
    assert written["dest"] == "/etc/crypto-policies/back-ends/sequoia.config"
    # Both rules are needed. sqv rejected the binding signature on
    # second-preimage resistance specifically, and easing only the collision
    # rule leaves the repository refused for the original reason.
    for rule in ("sha1.collision_resistance", "sha1.second_preimage_resistance"):
        assert rule in written["content"], rule


def test_the_opensearch_repository_is_still_signature_checked():
    """The fix eases one hash rule; it must not become "stop verifying".

    `trusted=yes` is the obvious shortcut and would make this whole failure go
    away, on the host that holds the range's logs. If someone reaches for it
    later, this is the test that should stop them.

    Read from the parsed task rather than the file's text. The first version of
    this grepped the source, which fails on the comment that explains why
    `trusted=yes` was rejected -- a test that forbids naming the thing it
    forbids, and that would push the next person to delete the reasoning in
    order to get green.
    """
    tasks = yaml.safe_load(
        (COLLECTOR / "tasks/sink-opensearch.yml").read_text(encoding="utf-8"))
    repo = next(t for t in tasks if "opensearch repository" in t.get("name", ""))
    line = repo["ansible.builtin.apt_repository"]["repo"]
    assert "trusted=yes" not in line, line
    assert "signed-by=/etc/apt/keyrings/opensearch.pgp" in line, line
