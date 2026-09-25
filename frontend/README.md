# redStackPRO canvas

The canvas is a view onto the topology. Every action goes through the API: the
palette, the overlay forms, validation, and compile all come from the backend,
so a new node kind is a file in `schema/registry/kinds` and not a change here.

## Run

    cd frontend
    npm install
    npm run dev

Expects the API on `http://127.0.0.1:8000`. Override with `REDSTACKPRO_API`.

    npm test        conversion tests, no browser needed
    npm run build   production bundle into dist/

## The export panel

The right hand panel switches between the inspector and the working directory
the topology compiles to: the file tree, the generated HCL, the inventory. That is
deliberate. redStackPRO does not run anything, so the code is the deliverable and
hiding it behind a download button would misrepresent the product.

The panel opens on `terraform/firewall.tf`, which is derived entirely from
edges. A rule exists there because someone drew a line, and nothing else in the
export shows that as directly.

## How it draws

Containment is nesting, not lines. A host dropped inside a segment is an
`attached` edge; a segment inside a network is another. Attachment is most of
the edges in any real topology, and drawing them all buries the relationships that
matter.

Drawn lines are `fronts`, `logs_to`, and `manages`, and the role follows from
what the line connects, so the canvas never asks which one you meant.

Validation runs against the API on every settled change, so what the canvas
shows and what the compiler will refuse are the same rules rather than two
implementations that drift.

## Icons

Tabler Icons, MIT, vendored in `src/icons.jsx` rather than fetched at runtime,
because the audience includes environments with no outbound access. The registry
names them; this supplies the paths.
