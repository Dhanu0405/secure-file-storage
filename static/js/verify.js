document.getElementById('fileInput').addEventListener('change', async function () {
    const file = this.files[0];
    if (!file) return;

    // Update the upload area to show selected file
    const uploadLabel = document.querySelector('.file-upload-label');
    const uploadIcon = uploadLabel.querySelector('i');
    const uploadText = uploadLabel.querySelector('span');
    
    // Store original content
    if (!uploadLabel.dataset.originalIcon) {
        uploadLabel.dataset.originalIcon = uploadIcon.className;
        uploadLabel.dataset.originalText = uploadText.textContent;
    }

    // Update with file name
    uploadIcon.className = 'fas fa-file-alt';
    uploadText.textContent = file.name;

    // Calculate hash
    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    // Update hash result
    const resultBox = document.getElementById('hashResult');
    const hashContent = resultBox.querySelector('.hash-content');
    resultBox.style.display = 'block';
    hashContent.textContent = hashHex;

    // Show copy button
    const certutilCmd = `certutil -hashfile "${file.name}" SHA256`;
    const copyBtn = document.getElementById('copyCertutil');
    copyBtn.style.display = 'inline-flex';

    copyBtn.onclick = () => {
        navigator.clipboard.writeText(certutilCmd).then(() => {
            const copiedMsg = document.getElementById('copiedMsg');
            copiedMsg.style.display = 'flex';
            setTimeout(() => {
                copiedMsg.style.display = 'none';
            }, 2000);
        });
    };
});

// Add click handler to reset the upload area
document.querySelector('.file-upload-label').addEventListener('click', function(e) {
    // Only reset if clicking the label directly (not when a file is selected)
    if (e.target === this) {
        const uploadIcon = this.querySelector('i');
        const uploadText = this.querySelector('span');
        
        // Restore original content if it exists
        if (this.dataset.originalIcon) {
            uploadIcon.className = this.dataset.originalIcon;
            uploadText.textContent = this.dataset.originalText;
        }
    }
});