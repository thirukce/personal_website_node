document.addEventListener('DOMContentLoaded', () => {
    // --- Reusable Form Toggling Logic (with focus) ---
    // Toggles form visibility and focuses the first input field.
    const toggleForm = (buttonId, formId) => {
        const button = document.getElementById(buttonId);
        const form = document.getElementById(formId);
        if (button && form) {
            button.addEventListener('click', () => {
                form.classList.toggle('hidden');
                // If the form is now visible, focus its first input or textarea
                if (!form.classList.contains('hidden')) {
                    const firstInput = form.querySelector('input, textarea');
                    if (firstInput) {
                        firstInput.focus();
                    }
                }
            });
        }
    };

    // Assign toggling behavior to all "Add" buttons
    toggleForm('add-task-btn',     'checklist-form');
    toggleForm('add-note-btn',     'notes-form');
    toggleForm('add-file-btn',     'upload-form');
    toggleForm('add-reminder-btn', 'reminder-form');

    // --- Delete Confirmation Logic ---
    // Adds a confirmation prompt before submitting any delete form.
    document.querySelectorAll('.delete-btn').forEach(button => {
        button.addEventListener('click', (event) => {
            // The button is inside a form. To prevent submission, we must prevent the default click action.
            if (!confirm('Are you sure you want to delete this item?')) {
                event.preventDefault();
            }
        });
    });

    // --- File Upload Logic (AJAX with Drag & Drop) ---
    const uploadForm = document.getElementById('upload-form');
    const uploadArea = document.querySelector('.upload-area');
    const fileInput = document.getElementById('file-input');
    const uploadLabel = document.querySelector('.upload-label');

    if (uploadForm && uploadArea && fileInput && uploadLabel) {
        const updateUploadLabel = (fileName) => {
            uploadLabel.innerHTML =
                `<i class="fas fa-file" style="font-size: 2rem; margin-bottom: 1rem; display: block;"></i>
                 Selected: ${fileName}`;
        };

        // Handle file selection via the input
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                updateUploadLabel(fileInput.files[0].name);
            }
        });

        // Drag and Drop listeners
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = '#ffd700';
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.style.borderColor = 'rgba(255, 255, 255, 0.3)';
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'rgba(255, 255, 255, 0.3)';
            if (e.dataTransfer.files.length > 0) {
                fileInput.files = e.dataTransfer.files;
                fileInput.dispatchEvent(new Event('change')); // Trigger change to update label
            }
        });

        // Handle form submission with Fetch API for a smoother UX
        uploadForm.addEventListener('submit', async function(event) {
            event.preventDefault();

            if (fileInput.files.length === 0) {
                alert('Please select a file to upload.');
                return;
            }

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);

            try {
                const response = await fetch(this.action, {
                    method: 'POST',
                    body: formData,
                });

                if (response.ok) {
                    alert('File uploaded successfully!');
                    window.location.reload(); // Reload to see the new file
                } else {
                    const errorText = await response.text();
                    alert('Upload failed: ' + errorText);
                }
            } catch (error) {
                console.error('An unexpected error occurred during upload:', error);
                alert('An unexpected error occurred. Please try again.');
            }
        });
    }

    // --- Inactivity Logout Logic ---
    const body = document.body;
    const inactivityTime = parseInt(body.dataset.sessionMaxAge, 10);
    const basePath = body.dataset.basePath || '';

    if (inactivityTime && !isNaN(inactivityTime)) {
        let timeout;
        const logout = () => window.location.href = `${basePath}/logout?reason=inactive`;
        const resetTimer = () => {
            clearTimeout(timeout);
            timeout = setTimeout(logout, inactivityTime);
        };
        ['load', 'mousemove', 'mousedown', 'touchstart', 'click', 'keydown', 'scroll'].forEach(eventName => {
            window.addEventListener(eventName, resetTimer, true);
        });
    }
});