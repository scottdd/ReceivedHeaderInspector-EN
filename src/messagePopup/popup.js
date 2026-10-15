//#####################################
//#####################################
//#### Functions for querying the Google DNS API https://dns.google/resolve?


// Resolve a domain and return its associated IP addresses
async function resolveDomain(domain) {
    const url = `https://dns.google/resolve?name=${domain}&type=A`; // Use the Google DNS API to fetch the IP
    try {
        const response = await fetch(url);
        const data = await response.json();
        if (data.Answer) {
            const ipAddresses = data.Answer.map(entry => entry.data); // Extract the IP addresses
			//console.log(ipAddresses);
            return ipAddresses;
        } else {
            console.log("No IP found for domain:", domain);
            return null;
        }
    } catch (error) {
        console.error("Error while fetching IPs for domain:", error);
        return null;
    }
}

// Fetch the SPF record of a domain
async function getSPFRecord(domain) {
    const url = `https://dns.google/resolve?name=${domain}&type=TXT`; // Query TXT records (SPF)
    try {
        const response = await fetch(url);
        const data = await response.json();
        if (data.Authority) {
			const spfRecords = data.Authority.map(entry => entry.data); // Extract SPF records (Authority response case)
			//console.log(spfRecords);
            return spfRecords;
        } else if (data.Answer) {
			const spfRecords = data.Answer.map(entry => entry.data); // Extract SPF records (Answer response case)
			//console.log(spfRecords);
            return spfRecords;
        } else {
            console.log("No SPF record found for this domain.");
            return null;
        }
    } catch (error) {
        console.error("Error while fetching SPF record:", error);
        return null;
    }
}


//#####################################
//#####################################






// A function must be declared async if it
// uses asynchronous operations (such as fetch(), setTimeout(), or Promise).

// From: "test.detection@hotmail.com" <sender@e9mail.com>
function extractEmail(fromHeader) {
    let email = null;

    // Check whether the email address is enclosed in < >
    const match = fromHeader.match(/<([^>]+)>/);
    if (match) {
        // Take the email address between the angle brackets
        email = match[1];
    } else {
        // No angle brackets: look for a plain email address
        const simpleMatch = fromHeader.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
        if (simpleMatch) {
            email = simpleMatch[0];
        }
    }

    return email;
}






async function analyzeEmailHeaders() {
    try {
		
		// The last server is the delivery server,
		// i.e. our own mail server,
		// so there is no point tracing it
		let firstPass = true;
		
        // Get the message displayed in the current tab
		// The user clicked our button, get the active tab in the current window using
		// the tabs API.
        let tabs = await messenger.tabs.query({ active: true, currentWindow: true });
		// Get the message currently displayed in the active tab, using the
		// messageDisplay API. Note: This needs the messagesRead permission.
		// The returned message is a MessageHeader object with the most relevant
		// information.		
        let message = await messenger.messageDisplay.getDisplayedMessage(tabs[0].id);

        if (!message) {
            console.error("No message displayed.");
            return;
        }
		
		
		// Fill in the HTML fields with the message subject and author
        document.getElementById("subject").textContent = message.subject || browser.i18n.getMessage("subjectUnavailable");
        document.getElementById("from").textContent = message.author || browser.i18n.getMessage("authorUnavailable");
		



	
        // Get the full message content
        let full = await messenger.messages.getFull(message.id);

		let sender = '';
		
		// Handle case variants of the "sender" header
		const senderHeaders = [
			'sender', 
			'X-sender', 
			'Sender'
		];
		
		// Check each header key variant
		for (let header of senderHeaders) {
			if (full.headers[header]) {
				sender = full.headers[header];
				break; // Stop at the first match
			}
		}
		
		// If it is an array, take the first element
		if (Array.isArray(sender)) {
			sender = sender[0];
		}
		// Otherwise it is a single occurrence; nothing to do
		
		document.getElementById("sender").textContent = sender || "";
		
		


        // Get the full "Received" headers
        let receivedHeader = full.headers["received"];

        // Prepare containers for the results
        let extractedServers = [];
		extractedServers['Ip'] = [];
		extractedServers['Hostname'] = [];


		let ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

		let hostnameRegex = /\b(?=[^\s]*[a-zA-Z])[^\s=+]+(?:\.[^\s=+]+)+\b/g;      // At least one dot; any non-space characters (including special ones) except = and +
		
        // Apply the regexes to each "Received" line
        if (Array.isArray(receivedHeader)) {

            for (let line of receivedHeader) {


				// Global (g) regexes must have lastIndex reset to zero before reuse.
				// This ensures exec always starts at the beginning of the string.
				hostnameRegex.lastIndex = 0;
				ipRegex.lastIndex = 0;

				
				let hostname = hostnameRegex.exec(line);
				let ip = ipRegex.exec(line);

				if(hostname)
				hostname = hostname['0'];
				if(ip)
				ip = ip['0'];

		if ( hostname ) {
			if(!firstPass)
			extractedServers['Hostname'].push(hostname);
			
			firstPass = false;
		}
		
		if (ip) {
			extractedServers['Ip'].push(ip);
		}
				

  
				
            }
        } else if (receivedHeader) {

				
				let line = receivedHeader;
				
				hostnameRegex.lastIndex = 0;
				ipRegex.lastIndex = 0;

				
				let hostname = hostnameRegex.exec(line);
				let ip = ipRegex.exec(line);

				if(hostname)
				hostname = hostname['0'];
				if(ip)
				ip = ip['0'];

		if ( hostname ) {
			if(!firstPass)
			extractedServers['Hostname'].push(hostname);
			
			firstPass = false;
		}
		
		if (ip) {
			extractedServers['Ip'].push(ip);
		}


        }



		// Reverse the result arrays
		//extractedServers['Hostname'] = extractedServers['Hostname'].reverse();		
		//extractedServers['Ip'] = extractedServers['Ip'].reverse();		
		
		
		// Thunderbird add-on review flags innerHTML as a security issue
		//document.getElementById("hostname").innerHTML  = extractedServers['Hostname'];
        //document.getElementById("ip").innerHTML  = extractedServers['Ip'];
		

		let container = document.getElementById('hostname');
		
	
		// Loop over each entry and create an element for it
		extractedServers['Hostname'].forEach(mot => {
			const span = document.createElement('span');  // Use <span> instead of <p>
			span.textContent = mot;  // Put the text in the <span>
			container.appendChild(span);  // Append the <span> to the container
		
			// Add a line break with a <br>
			container.appendChild(document.createElement('br'));
		});	



		container = document.getElementById('ip');
	
		// Loop over each entry and create an element for it
		extractedServers['Ip'].forEach(mot => {
			const span = document.createElement('span');  // Use <span> instead of <p>
			span.textContent = mot;  // Put the text in the <span>
			container.appendChild(span);  // Append the <span> to the container
		
			// Add a line break with a <br>
			container.appendChild(document.createElement('br'));
		});	






if( extractedServers['Ip']['0'] && extractedServers['Hostname']['0'] )
{



container = document.getElementById('qequoi1');
const span01 = document.createElement('span');
span01.textContent = extractedServers['Hostname']['0'];
span01.style.color = "blue";
span01.style.fontWeight = "bold";
container.appendChild(span01);
//container.appendChild(document.createElement('br'));
 
 
resolveDomain(extractedServers['Hostname']['0']).then(ips => {
    if (ips) {
        // Results are now available in `ips`
        //console.log(ips);
		
		container = document.getElementById('apireverseip');
		const span02 = document.createElement('span');
		span02.textContent = ips.join(", ");
		container.appendChild(span02);
		//container.appendChild(document.createElement('br')); // Add an empty line		

		
    } else {
        console.log("No IP found for the domain.");
    }
});

getSPFRecord(extractedServers['Hostname']['0']).then(spfRecords => {
    if (spfRecords) {
        // Results are now available in `spfRecords`
        //console.log(spfRecords);
		
		container = document.getElementById('apispfserveur');
		const span03 = document.createElement('span'); // Create a <span>
		span03.textContent = spfRecords.join(", ");
		container.appendChild(span03);
		//container.appendChild(document.createElement('br')); // Add an empty line		
		
    } else {
        console.log("No SPF record found for the domain.");
    }
});


    // Use a regex to extract the domain from the email address
	
	// First get the email address from the From line (message.author)
	// Example From: From: "test.detection@hotmail.com" <sender@e9mail.com>
	const email = extractEmail(message.author);
	//console.log('email:', email);
    const regex = /@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/;
    //const match = message.author.match(regex);
    const domain = email.match(regex);
	//console.log('domain:', domain[1]);
	
	// Run the SPF query only if the email domain differs from the sending server domain (already handled)
    if (domain && domain[1] && domain[1]!=extractedServers['Hostname']['0'] ) {
        // The domain is the regex's first capture group
        //console.log('Extracted domain:', domain[1]);

		container = document.getElementById('qequoi2');
		const span04 = document.createElement('span'); // Create a <span>
		span04.textContent = domain[1];
		span04.style.color = "blue";
		span04.style.fontWeight = "bold";
		container.appendChild(span04); // Append the text
		//container.appendChild(document.createElement('br')); // Add an empty line


		// Then run the SPF query
		getSPFRecord(domain[1]).then(spfRecords => {
			if (spfRecords) {
				// Results are now available in `ips`
				//console.log(spfRecords);
				//console.log(spfRecords.join(", "));
				
				container = document.getElementById('apispfemail');
				const span05 = document.createElement('span'); // Create a <span>
				// Join `spfRecords` into a comma-separated string
				span05.textContent = spfRecords.join(", ");
				container.appendChild(span05); // Append the text
				//container.appendChild(document.createElement('br')); // Add an empty line			
				
			} else {
				console.log("No SPF record found for the domain.");
			}
		});


    }	
	



}







    } catch (error) {
        console.error("An error occurred while processing the email:", error);

        // On error, show an error message in the HTML fields
        document.getElementById("subject").textContent = browser.i18n.getMessage("errorSubject");
        document.getElementById("from").textContent = browser.i18n.getMessage("errorFrom");
        document.getElementById("received").textContent = browser.i18n.getMessage("errorServer");
    }
}

// Localize static popup labels (elements with a data-i18n attribute)
function localizePage() {
    document.querySelectorAll("[data-i18n]").forEach(el => {
        const msg = browser.i18n.getMessage(el.dataset.i18n);
        if (msg || el.dataset.i18n === "reminderPrefix") {
            el.textContent = msg;
        }
    });
    document.title = browser.i18n.getMessage("actionTitle") || document.title;
}

localizePage();

// Run the analysis
analyzeEmailHeaders();
