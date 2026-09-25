import React from "react";
import { record, snapshot } from "./diagnostics.js";

// Catches a render exception in the canvas so a crash shows a recoverable panel
// with copyable diagnostics rather than a blank page. Blank-on-bad-coordinate
// does not throw and so does not land here; the diagnostics banner in App
// handles that. This is the harder failure, an actual exception, kept from
// taking the whole editor down with it.
export class CanvasErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    record("crash", { message: String(error?.message || error), componentStack: info?.componentStack });
  }

  copy = async () => {
    const doc = this.props.getDocument?.();
    const payload = snapshot(doc, {
      crash: { message: String(this.state.error?.message || this.state.error), stack: this.state.error?.stack },
    });
    try {
      await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
      this.setState({ copied: true });
    } catch {
      this.setState({ copied: false });
    }
  };

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="rg-crash">
        <h2>The canvas hit an error</h2>
        <p>{String(this.state.error?.message || this.state.error)}</p>
        <p className="rg-hint">
          Nothing was deployed and your work is still in memory. Copy the
          diagnostics, then reload to recover.
        </p>
        <div className="rg-crash-actions">
          <button type="button" onClick={this.copy}>
            {this.state.copied ? "Copied" : "Copy diagnostics"}
          </button>
          <button type="button" onClick={() => window.location.reload()}>
            Reload
          </button>
        </div>
      </div>
    );
  }
}
