document.getElementById('fileInput').addEventListener('change', async function() {
    const file = this.files[0];
    if (!file) return;

    const arrayBuffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    document.getElementById('hashOutput').innerHTML = `<strong>SHA-256 Hash:</strong><br>${hashHex}`;
});