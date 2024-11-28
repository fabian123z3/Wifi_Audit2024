document.addEventListener("DOMContentLoaded", () => {
    const interfaceSelect = document.getElementById("interface");
    const resultDiv = document.getElementById("result");

    // Función para manejar errores
    function handleError(message) {
        console.error(message);
        resultDiv.innerHTML = `<pre class="error">Error: ${message}</pre>`;
    }

    // Cargar las interfaces WiFi
    fetch("/list_interfaces")
        .then(response => response.json())
        .then(data => {
            interfaceSelect.innerHTML = "";
            const wirelessInterfaces = data.interfaces.filter(iface => iface.startsWith("wl"));
            if (wirelessInterfaces.length === 0) {
                handleError("No se encontraron interfaces inalámbricas.");
                return;
            }
            wirelessInterfaces.forEach(iface => {
                const option = document.createElement("option");
                option.value = iface;
                option.textContent = iface;
                interfaceSelect.appendChild(option);
            });
        })
        .catch(err => handleError(`Error al cargar interfaces: ${err.message}`));

    // Escanear redes WiFi
    document.getElementById("scanWifiButton").addEventListener("click", async () => {
        const interface = interfaceSelect.value;
        if (!interface) {
            handleError("Selecciona una interfaz.");
            return;
        }
        try {
            const response = await fetch(`/scan_wifi?interface=${encodeURIComponent(interface)}`);
            const data = await response.json();
            if (data.networks) {
                resultDiv.innerHTML = `
                    <table>
                        <thead>
                            <tr>
                                <th>SSID</th>
                                <th>BSSID</th>
                                <th>Canal</th>
                                <th>Calidad</th>
                                <th>Encriptación</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.networks.map(network => `
                                <tr>
                                    <td>${network.SSID || "N/A"}</td>
                                    <td>${network.BSSID || "N/A"}</td>
                                    <td>${network.Channel || "N/A"}</td>
                                    <td>${network.Quality || "N/A"}</td>
                                    <td>${network.Encryption || "N/A"}</td>
                                </tr>
                            `).join("")}
                        </tbody>
                    </table>`;
            } else {
                handleError(data.error || "No se encontraron redes.");
            }
        } catch (error) {
            handleError(`Error al escanear redes: ${error.message}`);
        }
    });

    // Capturar handshake
    document.getElementById("captureHandshakeButton").addEventListener("click", async () => {
        const interface = interfaceSelect.value;
        const bssid = document.getElementById("bssid").value;
        const channel = document.getElementById("channel").value;

        if (!interface || !bssid || !channel) {
            handleError("Todos los campos son obligatorios.");
            return;
        }

        try {
            const response = await fetch("/capture_handshake", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({ interface, bssid, channel }),
            });
            const data = await response.json();
            resultDiv.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
        } catch (error) {
            handleError(`Error al capturar handshake: ${error.message}`);
        }
    });

    // Crackear contraseña
    document.getElementById("crackPasswordButton").addEventListener("click", async () => {
        const capFile = document.getElementById("capFile").files[0];
        const dictFile = document.getElementById("dictFile").files[0];

        if (!capFile || !dictFile) {
            handleError("Todos los campos son obligatorios.");
            return;
        }

        const formData = new FormData();
        formData.append("handshakeFile", capFile);
        formData.append("dictFile", dictFile);

        try {
            const response = await fetch("/crack_password", {
                method: "POST",
                body: formData,
            });
            const data = await response.json();
            if (data.password) {
                resultDiv.innerHTML = `<pre>Contraseña encontrada: ${data.password}</pre>`;
            } else if (data.message) {
                resultDiv.innerHTML = `<pre>${data.message}</pre>`;
            } else {
                handleError(data.error || "No se encontró la contraseña.");
            }
        } catch (error) {
            handleError(`Error al crackear contraseña: ${error.message}`);
        }
    });
});
