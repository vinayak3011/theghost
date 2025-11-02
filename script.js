const experimentData = {
// 'ICT': [
//     { title: 'EXP 1 Study of OSINT framework.', file: 'files/ict/exp1.txt' },
//     { title: 'EXP 2 Perform Brute Force attack using Burp suite.', file: 'files/ict/exp2.txt' },
//     { title: 'EXP 3 To learn simulation of SQL injection attack.', file: 'files/ict/exp3.txt' },
//     { title: 'EXP 4 Demonstrate cross-site scripting attack.', file: 'files/ict/exp4.txt' },
//     { title: 'EXP 5 Use Metasploit To exploit (Kali Linux)', file: 'files/ict/exp5.txt' },
//     { title: 'EXP 6 Performing a Buffer Overflow attack Using Metasploit', file: 'files/ict/exp6.txt' },
//     { title: 'EXP 7 Use NMap scanner to perform port scanning of various forms – PING SCAN, ACK, SYN, NULL, XMAS', file: 'files/ict/exp7.txt' },
//     { title: 'EXP 8 Study the behavior of protections such as IDF and firewalls when altering headers in network packets.', file: 'files/ict/exp8.txt' },
//     { title: 'EXP 9 Study of steganography tools (Beyond syllabus)', file: 'files/ict/exp9.txt' }
// ],
'OSINT': [
    { title: 'EXP 1: Perform Email Header Analysis for extracting valuable information like sender IP address, email servers, and routing information', file: 'files\\OSINT\\EXP_1_OSINT.txt' },

    { title: "EXP 1 scenario Based: The cybersecurity team received a suspicious email claiming to\nbe from the university’s IT department. You are tasked to analyze\nits email header to:\n● Identify the actual sender’s IP address,\n● Verify if the email passed SPF/DKIM checks, and\n● Determine if the email was spoofed.", file: "files\\OSINT\\new osint exp\\exp 1.txt" },
    { title: 'EXP 2: Conduct email address enumeration by attempting to verify the existence of email addresses within a target domain using tools like TheHarvester or thehunter.io to find email addresses associated with a specific domain', file: 'files\\OSINT\\EXP_2_OSINT.txt' },
    { title: "EXP 2 scenario Based: A company reports delayed email deliveries. You are asked to\nextract the routing path from the email header and identify which\nmail server caused the delay based on timestamp analysis.", file: "files\\OSINT\\new osint exp\\exp 2.txt" },
    { title: 'EXP 3: Analyze the metadata of an email, including date and time stamps, email clients used, originating IP address, email’s origin, potential geographic location of the sender, and possible email routing', file: 'files\\OSINT\\EXP_3_OSINT.txt' },
    { title: "EXP 3 scenario Based: A phishing email was sent to multiple employees from a Gmail\naccount. Use the email header to trace the email’s journey and\napproximate geographic location of the sender.", file: "files\\OSINT\\new osint exp\\exp 3.txt" },
    { title: "EXP 4: As a penetration tester, you are assessing the exposure of staff\nemail IDs of infosec.edu. Using theHarvester and Hunter.io,\nenumerate possible email addresses and verify their existence.", file: "files\\OSINT\\EXP_4_OSINT.txt" },
    { title: 'EXP 4 scenario Based: Use OSINT tools such as TheHarvester to gather publicly available information (emails, subdomains, hosts, employee names, open ports, banners) from search engines, PGP key servers and other public sources', file: 'files\\OSINT\\new osint exp\\exp 4.txt' },
    { title: 'EXP 5: Perform reverse image analysis to find the physical location where content was captured by using image metadata, landmarks, street signs, or other visual cues to identify geolocation', file: 'files\\OSINT\\EXP_5_OSINT.txt' },
    { title: "EXP 5 scenario Based: You have been hired to assess an organization’s email\nfootprint. Using enumeration tools, identify valid corporate email addresses from public sources and document their data\nexposure risk.", file: "files\\OSINT\\new osint exp\\exp 5.txt" },
    { title: 'EXP 6: Gather tactical information using WHOIS/DomainTools, archives, reverse image search, EXIF data, source code, SSL certificates, robots/sitemaps, port scans, reverse IP lookup, mentions and other OSINT sources to profile a target', file: 'files\\OSINT\\EXP_6_OSINT.txt' },
    { title: "EXP 6 scenario Based: A malicious email attachment was shared internally. Extract\nand analyze the metadata of the email (.eml) to determine:\n● The originating IP address\n● The email client or software used\n● The exact timestamp of sending", file: "files\\OSINT\\new osint exp\\exp 6.txt" },
    { title: 'EXP 7: Use OSINT tools to identify technologies and frameworks used by a website (CMS, server software, programming languages, analytics) and create a vulnerability/technology-report', file: 'files\\OSINT\\EXP_7_OSINT.txt' },
    { title: "EXP 7 scenario Based: During an investigation, two copies of a suspicious email were\nfound on different devices. Compare the metadata of both and\nidentify if one of them has been tampered with or altered.", file: "files\\OSINT\\new osint exp\\exp 7.txt" },
    { title: 'EXP 8: Determine the geolocation (country, region, city — approximate) for at least 10 IP addresses using GeoIP databases, WHOIS, reverse DNS, traceroute and web APIs', file: 'files\\OSINT\\EXP_8_OSINT.txt' },
],

'DevSecOps': [
    { title: 'EXP 1 Download, install nmap and use it with different options to scan open ports, perform OS fingerprinting, ping scan, tcp port scan, udp port scan, etc.', file: 'files/cns/Exp_1.txt' },
    { title: 'EXP 2 Study the use of network reconnaissance tools like WHOIS, dig, traceroute, nslookup to gather information about networks and domain registrars.', file: 'files/cns/Exp_2.txt' },
    { title: 'EXP 3 Study of packet sniffer tools Wireshark: a. Observe performance in promiscuous as well as non-promiscuous mode. b. Show packets can be traced using different filters.', file: 'files/cns/Exp_3.txt' },
    { title: 'EXP 4 Breaking the Mono-alphabetic Substitution Cipher using Frequency Analysis Method.', file: 'files/cns/Exp_4.txt' },
    { title: 'EXP 5 Design and implement a product cipher using Substitution ciphers.', file: 'files/cns/Exp_5.txt' },
    { title: 'EXP 6 Encrypt long messages using various modes of operation using AES or DES.', file: 'files/cns/Exp_6.txt' },
    { title: 'EXP 7 Study of malicious software using different tools: a. Keylogger attack using keylogger tool. b. Simulate DoS attack using Hping or other tools. c. Use NESSUS/ISO Kali Linux to scan network for vulnerabilities.', file: 'files/cns/Exp_7.txt' },
    { title: 'EXP 8 Study of Network Security: a. Set up IPSec under Linux. b. Set up Snort and study the logs. c. Explore GPG tool to implement email security.', file: 'files/cns/Exp_8.txt' },
    { title: 'EXP 9 Content Beyond the Syllabus: a. Burp Suite Tool. b. Steghide Tool.', file: 'files/cns/Exp_9.txt' }
],
'AIML': [
    { title: 'EXP 1 Download, install nmap and use it with different options to scan open ports, perform OS fingerprinting, ping scan, tcp port scan, udp port scan, etc.', file: 'files/cns/Exp_1.txt' },
    { title: 'EXP 2 Study the use of network reconnaissance tools like WHOIS, dig, traceroute, nslookup to gather information about networks and domain registrars.', file: 'files/cns/Exp_2.txt' },
    { title: 'EXP 3 Study of packet sniffer tools Wireshark: a. Observe performance in promiscuous as well as non-promiscuous mode. b. Show packets can be traced using different filters.', file: 'files/cns/Exp_3.txt' },
    { title: 'EXP 4 Breaking the Mono-alphabetic Substitution Cipher using Frequency Analysis Method.', file: 'files/cns/Exp_4.txt' },
    { title: 'EXP 5 Design and implement a product cipher using Substitution ciphers.', file: 'files/cns/Exp_5.txt' },
    { title: 'EXP 6 Encrypt long messages using various modes of operation using AES or DES.', file: 'files/cns/Exp_6.txt' },
    { title: 'EXP 7 Study of malicious software using different tools: a. Keylogger attack using keylogger tool. b. Simulate DoS attack using Hping or other tools. c. Use NESSUS/ISO Kali Linux to scan network for vulnerabilities.', file: 'files/cns/Exp_7.txt' },
    { title: 'EXP 8 Study of Network Security: a. Set up IPSec under Linux. b. Set up Snort and study the logs. c. Explore GPG tool to implement email security.', file: 'files/cns/Exp_8.txt' },
    { title: 'EXP 9 Content Beyond the Syllabus: a. Burp Suite Tool. b. Steghide Tool.', file: 'files/cns/Exp_9.txt' }
],
'AWX': [
    { title: 'EXP 1 Download, install nmap and use it with different options to scan open ports, perform OS fingerprinting, ping scan, tcp port scan, udp port scan, etc.', file: 'files/cns/Exp_1.txt' },
    { title: 'EXP 2 Study the use of network reconnaissance tools like WHOIS, dig, traceroute, nslookup to gather information about networks and domain registrars.', file: 'files/cns/Exp_2.txt' },
    { title: 'EXP 3 Study of packet sniffer tools Wireshark: a. Observe performance in promiscuous as well as non-promiscuous mode. b. Show packets can be traced using different filters.', file: 'files/cns/Exp_3.txt' },
    { title: 'EXP 4 Breaking the Mono-alphabetic Substitution Cipher using Frequency Analysis Method.', file: 'files/cns/Exp_4.txt' },
    { title: 'EXP 5 Design and implement a product cipher using Substitution ciphers.', file: 'files/cns/Exp_5.txt' },
    { title: 'EXP 6 Encrypt long messages using various modes of operation using AES or DES.', file: 'files/cns/Exp_6.txt' },
    { title: 'EXP 7 Study of malicious software using different tools: a. Keylogger attack using keylogger tool. b. Simulate DoS attack using Hping or other tools. c. Use NESSUS/ISO Kali Linux to scan network for vulnerabilities.', file: 'files/cns/Exp_7.txt' },
    { title: 'EXP 8 Study of Network Security: a. Set up IPSec under Linux. b. Set up Snort and study the logs. c. Explore GPG tool to implement email security.', file: 'files/cns/Exp_8.txt' },
    { title: 'EXP 9 Content Beyond the Syllabus: a. Burp Suite Tool. b. Steghide Tool.', file: 'files/cns/Exp_9.txt' }
],
};

document.getElementById('downloadAllButton').addEventListener('click', function () {
    window.location.href = 'files/cns/files.zip';
});


document.getElementById('subject').addEventListener('change', function () {
    const subject = this.value;
    const experimentContainer = document.getElementById('experimentContainer');
    const experimentSelect = document.getElementById('experiment');
    console.log(experimentSelect);
    
    // Clear previous content
    experimentSelect.innerHTML = '<option value="">Select Experiment</option>';
    document.getElementById('experimentTitle').textContent = '';
    document.getElementById('experimentContent').textContent = '';
    document.getElementById('downloadButton').style.display = 'none';

    // Hide copy button if it exists
    const existingCopyBtn = document.getElementById('copyButton');
    if (existingCopyBtn) {
        existingCopyBtn.remove();
    }

    // Show dropdown and populate if valid subject
    if (subject && experimentData[subject]) {
        experimentContainer.style.display = 'block';
        
        experimentData[subject].forEach(exp => {
            const option = document.createElement('option');
            option.value = exp.file;
            option.textContent = exp.title;
            experimentSelect.appendChild(option);
        });
    // } else if (experimentSelect == "") {
    } else {
        experimentContainer.style.display = 'none';
    }
});

document.getElementById('experiment').addEventListener('change', function () {
    const subject = document.getElementById('subject').value;
    const filePath = this.value;
    const experiment = experimentData[subject].find(e => e.file === filePath);

    if (!filePath || !experiment) return;

    fetch(filePath)
        .then(response => response.text())
        .then(data => {
            document.getElementById('experimentTitle').textContent = experiment.title;
            document.getElementById('experimentContent').textContent = data;

            // Show Download Button
            const downloadButton = document.getElementById('downloadButton');
            downloadButton.style.display = 'inline-block';
            downloadButton.onclick = function () {
                const blob = new Blob([data], { type: 'text/plain' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${experiment.title}.txt`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            };

              // Show or hide the "Download All" button based on EXP 4 selection
            const downloadAllButton = document.getElementById('downloadAllButton');
            if (subject === 'CNS' && filePath === 'files/cns/Exp_4.txt') {
                downloadAllButton.style.display = 'inline-block';
            } else {
                downloadAllButton.style.display = 'none';
            }

            // // Show Copy Button (if not already added)
            // if (!document.getElementById('copyButton')) {
            //     const copyBtn = document.createElement('button');
            //     copyBtn.id = 'copyButton';
            //     copyBtn.textContent = 'Copy to Clipboard';
            //     copyBtn.style.marginLeft = '10px';
            //     copyBtn.onclick = function () {
            //         navigator.clipboard.writeText(data).then(() => {
            //             alert('Copied to clipboard!');
            //         }).catch(err => {
            //             alert('Failed to copy!');
            //         });
            //     };
            //     downloadButton.parentNode.appendChild(copyBtn);
            // }

            let copyBtn = document.getElementById('copyButton');
            if (!copyBtn) {
                copyBtn = document.createElement('button');
                copyBtn.id = 'copyButton';
                copyBtn.textContent = 'Copy to Clipboard';
                copyBtn.style.marginLeft = '10px';
                downloadButton.parentNode.appendChild(copyBtn);
            }
            // Always update the onclick handler
            copyBtn.onclick = function () {
                navigator.clipboard.writeText(data).then(() => {
                    alert('Copied to clipboard!');
                }).catch(err => {
                    alert('Failed to copy!');
                });
            };

        });
});
