/**
 * Intentionally Vulnerable Search Results Component
 *
 * Vulnerability: dangerouslySetInnerHTML with unsanitized API response
 * If the server returns attacker-controlled HTML, this enables stored XSS.
 * Fix: sanitize with DOMPurify before rendering, or use a text-only renderer.
 */

interface Props {
  htmlContent: string
}

export function SearchResults({ htmlContent }: Props) {
  return (
    <div className="search-results">
      {/* [VULN] dangerouslySetInnerHTML — XSS if htmlContent contains user input */}
      <div dangerouslySetInnerHTML={{ __html: htmlContent }} />
    </div>
  )
}
