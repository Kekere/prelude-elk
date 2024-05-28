var selectedOrganization, RORIObject;

document.addEventListener("DOMContentLoaded", function () {
    if (localStorage.getItem("RORIString")) {
        RORIObject = JSON.parse(localStorage.getItem("RORIString"));
        extract();
    }
    if (sessionStorage.getItem("selectedOrganization")) {
        selectedOrganization = JSON.parse(sessionStorage.getItem("selectedOrganization"));
        let organizationIncidents = [];
        incidents.forEach(incident => {
            let temp = []; //intermediate variable that stores the ids of organizations
            if (String(typeof incident.id_organization) == "number") {
                temp.push(incident.id_organization);
            }
            else if (incident.id_organization.length != 0) {
                temp = incident.id_organization.split(",").map(Number);
            }
            if (temp.includes(selectedOrganization.id)) {
                organizationIncidents.push(incident);
            }
        });
        let availableIncidents = document.getElementById("availableIncidents");
        clearTable(availableIncidents);
        let assignedIncidents = document.getElementById("assignedIncidents");
        clearTable(assignedIncidents);
        incidents.forEach(incident => {
            if (organizationIncidents.includes(incident)) {
                let row = assignedIncidents.insertRow();
                row.setAttribute("class", "unhighlighted");
                row.setAttribute("data-value", incident.id);
                row.setAttribute("onclick", "selectAssignedIncident(this)");
                let name = row.insertCell(0);
                name.innerHTML = incident.name;
                let description = row.insertCell(1);
                description.innerHTML = incident.description;
                let riskLevel = row.insertCell(2);
                riskLevel.innerHTML = incident.risk_level;
            }
            else if (incident.id_organization == "") {
                let row = availableIncidents.insertRow();
                row.setAttribute("class", "unhighlighted");
                row.setAttribute("data-value", incident.id);
                row.setAttribute("onclick", "selectAvailableIncident(this)");
                let name = row.insertCell(0);
                name.innerHTML = incident.name;
                let description = row.insertCell(1);
                description.innerHTML = incident.description;
                let riskLevel = row.insertCell(2);
                riskLevel.innerHTML = incident.risk_level;
            }
        });
    }
    else {
        if (confirm("No organization was selected.")) {
            window.history.back(); //in case there was a problem while fetching the organization id
        }
    }
});

var availableIncidentSelected = false, availableIncidentId = 0;

function selectAvailableIncident(row) {
    let assignedIncidents = document.getElementById("assignedIncidents").rows;
    for (let incident of assignedIncidents) {
        incident.className = "unhighlighted";
    }
    assignedIncidentSelected = false;
    assignedIncidentId = 0;
    let availableIncidents = document.getElementById("availableIncidents").rows;
    for (let incident of availableIncidents) {
        if (incident != row) {
            incident.className = "unhighlighted";
        }
    }
    row.className = row.className == "unhighlighted" ? "highlighted" : "unhighlighted";
    availableIncidentSelected = row.className == "highlighted";
    availableIncidentId = Number.parseInt(row.getAttribute("data-value"));
}

var assignedIncidentSelected = false, assignedIncidentId = 0;

function selectAssignedIncident(row) {
    let availableIncidents = document.getElementById("availableIncidents").rows;
    for (let incident of availableIncidents) {
        incident.className = "unhighlighted";
    }
    availableIncidentSelected = false;
    availableIncidentId = 0;
    let assignedIncidents = document.getElementById("assignedIncidents").rows;
    for (let incident of assignedIncidents) {
        if (incident != row) {
            incident.className = "unhighlighted";
        }
    }
    row.className = row.className == "unhighlighted" ? "highlighted" : "unhighlighted";
    assignedIncidentSelected = row.className == "highlighted";
    assignedIncidentId = Number.parseInt(row.getAttribute("data-value"));
    if (assignedIncidentSelected) {
        let assignedIncident = getIncidentById(assignedIncidentId);
        let ale = getALEById(assignedIncident.id_ale);
        document.getElementById("la").value = ale.LA ? ale.LA : "0.00";
        document.getElementById("ld").value = ale.LD ? ale.LD : "0.00";
        document.getElementById("lr").value = ale.LR ? ale.LR : "0.00";
        document.getElementById("lp").value = ale.LP ? ale.LP : "0.00";
        document.getElementById("lrec").value = ale.LREC ? ale.LREC : "0.00";
        document.getElementById("lrpc").value = ale.LRPC ? ale.LRPC : "0.00";
        document.getElementById("ol").value = ale.OL ? ale.OL : "0.00";
        document.getElementById("ci").value = ale.CI ? ale.CI : "0.00";
        document.getElementById("aro").value = ale.ARO ? ale.ARO : "0.00";
        document.getElementById("totalValue").value = ale.total ? ale.total : getTotalAle(ale);
    }
}

function assignIncident() {
    if (!(availableIncidentSelected || assignedIncidentSelected)) {
        if (confirm("Please select a detrimental event."));
        return;
    }
    let totalValue = document.getElementById("totalValue").valueAsNumber;
    if (totalValue <= 0) {
        alert("Total value should be greater than 0.");
    }
    else {
        let totalChecked = document.getElementById("giveTotal").checked;
        let la = document.getElementById("la").valueAsNumber;
        let ld = document.getElementById("ld").valueAsNumber;
        let lr = document.getElementById("lr").valueAsNumber;
        let lp = document.getElementById("lp").valueAsNumber;
        let lrec = document.getElementById("lrec").valueAsNumber;
        let lrpc = document.getElementById("lrpc").valueAsNumber;
        let ol = document.getElementById("ol").valueAsNumber;
        let ci = document.getElementById("ci").valueAsNumber;
        let aro = document.getElementById("aro").valueAsNumber;
        let ale;
        let incident;
        if (availableIncidentId != 0) {
            incident = getIncidentById(availableIncidentId);
            ale = {
                id: getNewALEId(),
                LA: totalChecked ? "" : la,
                LD: totalChecked ? "" : ld,
                LR: totalChecked ? "" : lr,
                LP: totalChecked ? "" : lp,
                LREC: totalChecked ? "" : lrec,
                LRPC: totalChecked ? "" : lrpc,
                OL: totalChecked ? "" : ol,
                CI: totalChecked ? "" : ci,
                ARO: totalChecked ? "" : aro,
                total: totalValue,
            }
            annual_loss_expectancies.push(ale);
            incident.id_ale = ale.id;
            incident.id_organization = selectedOrganization.id;
        }
        else if (assignedIncidentId != 0) {
            incident = getIncidentById(assignedIncidentId);
            ale = getALEById(incident.id_ale);
            ale.LA = totalChecked ? "" : la;
            ale.LD = totalChecked ? "" : ld;
            ale.LR = totalChecked ? "" : lr;
            ale.LP = totalChecked ? "" : lp;
            ale.LREC = totalChecked ? "" : lrec;
            ale.LRPC = totalChecked ? "" : lrpc;
            ale.OL = totalChecked ? "" : ol;
            ale.CI = totalChecked ? "" : ci;
            ale.ARO = totalChecked ? "" : aro;
            ale.total = totalValue;
        }
        if (totalValue <= 100) {
            incident.risk_level = "low";
        }
        else if (totalValue <= 1000) {
            incident.risk_level = "medium";
        }
        else {
            incident.risk_level = "high";
        }
        incidents.forEach((inc, index) => {
            if (inc.id == incident.id) {
                incidents[index] = incident;
            }
        });
        annual_loss_expectancies.forEach((e, index) => {
            if (e.id == ale.id) {
                annual_loss_expectancies[index] = ale;
            }
        });
        RORIObject.incidents = incidents;
        RORIObject.annual_loss_expectancies = annual_loss_expectancies;
        localStorage.setItem("RORIString", JSON.stringify(RORIObject));
        window.location.reload();
    }
}

function removeIncident() {
    if (!assignedIncidentSelected) {
        alert("Please select a detrimental event.");
    }
    else {
        let incident = getIncidentById(assignedIncidentId);
        incident.id_organization = "";
        incidents.forEach((inc, index) => {
            if (inc == incident) {
                annual_loss_expectancies.forEach(ale => {
                    if (ale.id == incident.id_ale) {
                        let aleIndex = annual_loss_expectancies.indexOf(ale);
                        annual_loss_expectancies.splice(aleIndex, 1);
                    }
                });
                incident.id_ale = "";
                incident.risk_level = "";
                incidents[index] = incident;
                RORIObject.incidents = incidents;
                localStorage.setItem("RORIString", JSON.stringify(RORIObject));
                window.location.reload();
            }
        });
    }
}

function toggleTotal() {
    let totalChecked = document.getElementById("giveTotal").checked;
    let formElements = document.getElementById("aleForm").elements;
    if (totalChecked) {
        for (let element of formElements) {
            if (element.tagName == "INPUT" && element.type == "number") {
                if (element.id != "totalValue") {
                    element.disabled = true;
                }
                else {
                    element.disabled = false;
                }
            }
        }
    }
    else {
        for (let element of formElements) {
            if (element.tagName == "INPUT") {
                if (element.id == "totalValue") {
                    element.disabled = true;
                }
                else {
                    element.disabled = false;
                }
            }
        }
    }
}

function changeTotal() {
    let totalValue = document.getElementById("totalValue");
    let la = document.getElementById("la").valueAsNumber ? document.getElementById("la").valueAsNumber : 0;
    let ld = document.getElementById("ld").valueAsNumber ? document.getElementById("ld").valueAsNumber : 0;
    let lr = document.getElementById("lr").valueAsNumber ? document.getElementById("lr").valueAsNumber : 0;
    let lp = document.getElementById("lp").valueAsNumber ? document.getElementById("lp").valueAsNumber : 0;
    let lrec = document.getElementById("lrec").valueAsNumber ? document.getElementById("lrec").valueAsNumber : 0;
    let lrpc = document.getElementById("lrpc").valueAsNumber ? document.getElementById("lrpc").valueAsNumber : 0;
    let ol = document.getElementById("ol").valueAsNumber ? document.getElementById("ol").valueAsNumber : 0;
    let ci = document.getElementById("ci").valueAsNumber ? document.getElementById("ci").valueAsNumber : 0;
    let aro = document.getElementById("aro").valueAsNumber ? document.getElementById("aro").valueAsNumber : 0;
    totalValue.value = Math.m(Math.s(Math.a(la, Math.a(ld, Math.a(lr, Math.a(lp, Math.a(lrec, Math.a(lrpc, ol)))))), ci), aro);
}

function getIncidentById(incidentId) {
    let associatedIncident = {};
    incidents.forEach(incident => {
        if (incident.id == incidentId) {
            associatedIncident = incident;
        }
    });
    return associatedIncident;
}

function getALEById(aleId) {
    let associatedALE = {};
    annual_loss_expectancies.forEach(ale => {
        if (ale.id == aleId) {
            associatedALE = ale;
        }
    });
    return associatedALE;
}

function getTotalAle(ale) {
    return Math.m(Math.s(Math.a(ale.LA, Math.a(ale.LD, Math.a(ale.LR, Math.a(ale.LP, Math.a(ale.LREC, Math.a(ale.LRPC, ale.OL)))))), ale.CI), ale.ARO);
}

function getNewALEId() {
    let id = 1;
    annual_loss_expectancies.forEach(ale => {
        if (ale.id >= id) {
            id = ale.id + 1;
        }
    });
    return id;
}