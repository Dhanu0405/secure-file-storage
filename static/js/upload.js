
function updateFileName(input) {
    const fileName = input.files[0]?.name;
    const fileNameElement = document.getElementById('fileName');
    if (fileName) {
        fileNameElement.textContent = fileName;
    } else {
        fileNameElement.textContent = '';
    }
}

// Drag and drop functionality
const dropZone = document.querySelector('.file-upload-label');
const fileInput = document.querySelector('.file-upload-input');

['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, preventDefaults, false);
});

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, highlight, false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, unhighlight, false);
});

function highlight(e) {
    dropZone.classList.add('highlight');
}

function unhighlight(e) {
    dropZone.classList.remove('highlight');
}

dropZone.addEventListener('drop', handleDrop, false);

function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;
    fileInput.files = files;
    updateFileName(fileInput);
}