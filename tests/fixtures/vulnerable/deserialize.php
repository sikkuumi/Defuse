<?php
// The bug a Gemini-written test file exposed: a source the engine already
// tracked reaching a sink it did not have.
function restore() {
  // EXPECT-FLOW unsafe-deserialization
  return unserialize(base64_decode($_COOKIE['session']));
}
