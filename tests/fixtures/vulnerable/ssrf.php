<?php
function pull() {
  // EXPECT-FLOW ssrf
  return file_get_contents($_GET['url']);
}
function pullCurl() {
  $ch = curl_init();
  // EXPECT-FLOW ssrf
  curl_setopt($ch, CURLOPT_URL, $_POST['endpoint']);
  return curl_exec($ch);
}
function safe() {
  return file_get_contents('https://api.example.com/x');  // SAFE
}
