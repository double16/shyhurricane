// Shared data-flow regression fixture; extend with additional cases as needed.
document.getElementById("dataForm").addEventListener("submit", function (e) {
  submitData(this.getAttribute("method"), this.getAttribute("action"), new FormData(this));
  e.preventDefault();
});
function submitData(method, path, data) {
  const retry = tries => tries == 0 ? null : fetch(path, {
    method,
    headers: {
      "Content-Type": window.contentType
    },
    body: payload(data)
  }).then(res => res.status === 200 ? res.text().then(t => isNaN(t) ? t : t + " entries") : "Could not fetch data!").then(res => document.getElementById("dataResult").innerHTML = res).catch(e => retry(tries - 1));
  retry(3);
}
