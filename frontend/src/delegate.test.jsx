import React, { useState } from "react";
import { describe, expect, test } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { DelegateToPicker } from "./DelegateToPicker.jsx";

const GROUPS = [
  { host: "winterfell", kind: "dc", spns: [
    { spn: "CIFS/winterfell.north.local", label: "CIFS", about: "file and admin shares" },
    { spn: "LDAP/winterfell.north.local", label: "LDAP", about: "directory access, DCSync" },
  ] },
  { host: "castelblack", kind: "srv", spns: [
    { spn: "MSSQLSvc/castelblack.north.local:1433", label: "MSSQL", about: "SQL Server" },
  ] },
];

function Harness({ initial }) {
  const [value, setValue] = useState(initial);
  return (
    <>
      <DelegateToPicker value={value} groups={GROUPS} onChange={setValue} />
      <output data-testid="value">{JSON.stringify(value ?? null)}</output>
    </>
  );
}

const current = () => JSON.parse(screen.getByTestId("value").textContent);

describe("Delegate to picker", () => {
  test("lists each host's services and ticks the picked ones", () => {
    render(<Harness initial={["CIFS/winterfell.north.local"]} />);
    expect(screen.getByText("winterfell")).toBeTruthy();
    expect(screen.getByText("castelblack")).toBeTruthy();
    const cifs = screen.getAllByRole("checkbox")[0];
    expect(cifs.checked).toBe(true);
  });

  test("ticking and unticking edits the list", () => {
    render(<Harness initial={["CIFS/winterfell.north.local"]} />);
    const [cifs, , mssql] = screen.getAllByRole("checkbox");
    fireEvent.click(mssql);
    expect(current()).toEqual([
      "CIFS/winterfell.north.local", "MSSQLSvc/castelblack.north.local:1433"]);
    fireEvent.click(cifs);
    expect(current()).toEqual(["MSSQLSvc/castelblack.north.local:1433"]);
    fireEvent.click(screen.getAllByRole("checkbox")[2]);
    expect(current()).toBeNull();
  });

  test("an SPN typed by hand is added and shown as a removable chip", () => {
    render(<Harness initial={undefined} />);
    fireEvent.change(screen.getByLabelText("Other SPN"), { target: { value: "HTTP/web.north.local" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    expect(current()).toEqual(["HTTP/web.north.local"]);
    fireEvent.click(screen.getByRole("button", { name: "Remove HTTP/web.north.local" }));
    expect(current()).toBeNull();
  });

  test("with no other Windows host it says so and still takes a typed SPN", () => {
    render(<DelegateToPicker value={[]} groups={[]} onChange={() => {}} />);
    expect(screen.getByText(/No other Windows host in this domain yet/)).toBeTruthy();
    expect(screen.getByLabelText("Other SPN")).toBeTruthy();
  });
});
