// FIXTURE: Cross-site scripting, React/TSX.
export function Bio({ html }: { html: string }) {
  // EXPECT xss
  const markup = { __html: html };
  return <div dangerouslySetInnerHTML={markup} />;
}
