// FIXTURE: Cross-site scripting, JavaScript (browser).
function renderGreeting(el, userName) {
  // EXPECT xss
  el.innerHTML = "<b>Welcome " + userName + "</b>";
}

function renderComment(comment) {
  // EXPECT xss
  document.write("<p class='comment'>" + comment + "</p>");
}

function insertBadge(el, badge) {
  // EXPECT xss
  el.insertAdjacentHTML("beforeend", badge);
}
