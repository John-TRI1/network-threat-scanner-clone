setInterval(async () => {
    threatData = await fetch("/threats");
    threats = await threatData.json();  
    
    threatTable = document.getElementById("threatInfo");
    threatTable.innerHTML = "";

    if (threats && threats.length > 0) {
        threats.forEach(threat => {
            threatTable.innerHTML += `<tr>
                <td>${threat.ip}</td>
                <td>${threat.score}</td>
                <td>${threat.status}</td>
                <td>${threat.action}</td>
                <td>${threat.attacks}</td>
            </tr>`;
        });
    } else {
        threatTable.innerHTML = "<tr><td colspan='5'>No threats detected.</td></tr>";
    }
}, 3000);


document.getElementById("scanForm").addEventListener("submit", async function (e) {
    e.preventDefault();

    ip = document.getElementById("ipInput").value;

    await fetch("/start_scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: ip })
    });

    scanPoll = setInterval(async () => {
        scanData = await fetch("/scan-results");
        scanResults = await scanData.json();

        if (scanResults.status === "complete") {
            scanFinal = scanResults.data;
            scanTable = document.getElementById("scanResults");
            scanTable.innerHTML = "";

            if (scanFinal.all_hosts && scanFinal.all_hosts.length > 0) {
                scanFinal.all_hosts.forEach(host => {
                    method = scanFinal.alive.includes(host) ? "ICMP" : "ARP";
                    scanTable.innerHTML += `<tr>
                        <td>${host}</td>
                        <td>${method}</td>
                    </tr>`;
                });
            } else {
                scanTable.innerHTML = "<tr><td colspan='2'>No hosts found.</td></tr>";
            }
        }
    }, 2000);
});
