import BGPLSClient
import Testing

/// Assert that a topology-only fixture produced actual NLRI coordinates, not attribute coordinates.
func nlriDiagnostics(_ diagnostics: [LSRIB.UpdateDiagnostic])
    -> [(field: LSRIB.NLRIField, diagnostic: BGPLSNLRIParser.Diagnostic)]
{
    diagnostics.compactMap { issue in
        guard case .nlri(let field, let diagnostic) = issue else {
            Issue.record("expected an NLRI diagnostic, not an attribute issue")
            return nil
        }
        return (field, diagnostic)
    }
}
