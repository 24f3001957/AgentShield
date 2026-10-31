import { Link } from "react-router-dom";
import { EmptyState, PageHeader } from "../components/ui";

export default function NotFound() {
  return (
    <>
      <PageHeader eyebrow="404" title="Not found" />
      <EmptyState
        title="This view does not exist"
        message="The console has no route for that path."
        action={
          <Link className="btn btn--primary btn--sm" to="/">
            Back to dashboard
          </Link>
        }
      />
    </>
  );
}
