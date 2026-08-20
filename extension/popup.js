document.getElementById('startScan').addEventListener('click', async () => {
    const target = document.getElementById('target').value.trim();
    const mode = document.getElementById('mode').value;
    const statusDiv = document.getElementById('status');

    if (!target) {
        showStatus('Please enter a target', 'error');
        return;
    }

    try {
        const response = await fetch('http://127.0.0.1:5000/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ target, mode })
        });

        const result = await response.json();

        if (response.ok) {
            showStatus(`Scan started for ${target} (Mode ${mode})`, 'success');
        } else {
            showStatus(`Error: ${result.error}`, 'error');
        }
    } catch (error) {
        showStatus('Failed to connect to Athena server. Make sure it\'s running with mode 4.', 'error');
    }
});

function showStatus(message, type) {
    const statusDiv = document.getElementById('status');
    statusDiv.textContent = message;
    statusDiv.className = type;
}