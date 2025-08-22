document.addEventListener('DOMContentLoaded', () => {
    // --- Helper function to toggle form visibility ---
    const setupFormToggle = (buttonId, formId) => {
        const button = document.getElementById(buttonId);
        const form = document.getElementById(formId);
        if (button && form) {
            button.addEventListener('click', () => {
                form.classList.toggle('hidden');
                // Focus the first input in the form when it's shown
                if (!form.classList.contains('hidden')) {
                    const firstInput = form.querySelector('input, textarea');
                    if (firstInput) {
                        firstInput.focus();
                    }
                }
            });
        }
    };

    // --- Setup all form toggles ---
    setupFormToggle('add-task-btn', 'checklist-form');
    setupFormToggle('add-note-btn', 'notes-form');
    setupFormToggle('add-file-btn', 'upload-form');
    setupFormToggle('add-reminder-btn', 'reminder-form');

    // --- Session Timeout Logic ---
    const body = document.body;
    const sessionMaxAge = parseInt(body.dataset.sessionMaxAge, 10);
    const basePath = body.dataset.basePath || '';

    if (sessionMaxAge && sessionMaxAge > 0) {
        setTimeout(() => {
            // Redirect to logout with an 'inactive' reason
            alert('You have been logged out due to inactivity.');
            window.location.href = `${basePath}/logout?reason=inactive`;
        }, sessionMaxAge);
    }

    // --- Confirmation for Delete Forms ---
    const setupDeleteConfirmation = () => {
        document.querySelectorAll('form[action$="/delete"]').forEach(form => {
            form.addEventListener('submit', function(event) {
                let message = 'Are you sure you want to delete this item?';
                // Customize message based on the form's action URL
                if (form.action.includes('/checklist/')) {
                    message = 'Are you sure you want to delete this task?';
                } else if (form.action.includes('/notes/')) {
                    message = 'Are you sure you want to delete this note?';
                } else if (form.action.includes('/files/')) {
                    message = 'Are you sure you want to delete this file?';
                } else if (form.action.includes('/reminders/')) {
                    message = 'Are you sure you want to delete this reminder?';
                }

                if (!confirm(message)) {
                    event.preventDefault(); // Prevent form submission if user cancels
                }
            });
        });
    };

    // --- File Upload Drag & Drop UI ---
    const uploadArea = document.querySelector('.upload-area');
    const fileInput = document.getElementById('file-input');
    const uploadLabel = document.querySelector('.upload-label');
    const uploadForm = document.getElementById('upload-form');

    if (uploadArea && fileInput && uploadLabel && uploadForm) {
        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
            }, false);
        });

        // Highlight drop zone when item is dragged over it
        ['dragenter', 'dragover'].forEach(eventName => {
            uploadArea.addEventListener(eventName, () => {
                uploadArea.style.borderColor = '#ffd700'; // Use the same hover color
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, () => {
                uploadArea.style.borderColor = 'rgba(255, 255, 255, 0.3)'; // Reset border
            }, false);
        });

        const updateFileLabel = (file) => {
            if (file) {
                uploadLabel.innerHTML = `<i class="fas fa-file" style="margin-right: 8px;"></i> ${file.name}`;
            }
        };

        // Handle dropped files
        uploadArea.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            fileInput.files = files;
            updateFileLabel(files[0]);
        }, false);

        // Handle file selection via click
        fileInput.addEventListener('change', () => {
            updateFileLabel(fileInput.files[0]);
        });
    }

    // Handle file upload form submission via Fetch API
    if (uploadForm) {
        const uploadSubmitBtn = uploadForm.querySelector('button[type="submit"]');

        uploadForm.addEventListener('submit', async (e) => {
            e.preventDefault(); // Prevent default form submission

            if (!fileInput.files || fileInput.files.length === 0) {
                alert('Please select a file to upload.');
                return;
            }

            const formData = new FormData();
            formData.append('file', fileInput.files[0]); // 'file' must match multer's field name

            try {
                if (uploadSubmitBtn) {
                    uploadSubmitBtn.disabled = true; // Disable button during upload
                }
                const response = await fetch(uploadForm.action, {
                    method: 'POST',
                    body: formData,
                });

                const result = await response.text(); // Read as text, server sends simple string

                if (response.ok) {
                    alert('File uploaded successfully!');
                    window.location.reload(); // Reload dashboard to show new file
                } else {
                    alert(`Upload failed: ${result}`); // Display error message from server
                }
            } catch (error) {
                console.error('Error uploading file:', error);
                alert('An unexpected error occurred during upload.');
            } finally {
                if (uploadSubmitBtn) {
                    uploadSubmitBtn.disabled = false; // Re-enable button
                }
            }
        });
    }

    // Initialize delete confirmations
    setupDeleteConfirmation();
});