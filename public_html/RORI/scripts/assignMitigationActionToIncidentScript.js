var selectedIncident, assignedCountermeasures, RORIObject;

document.addEventListener("DOMContentLoaded", function () {
    if (localStorage.getItem("RORIString")) {
        RORIObject = JSON.parse(localStorage.getItem("RORIString"));
        extract();
    }
    if (sessionStorage.getItem("selectedIncident")) {
        selectedIncident = JSON.parse(sessionStorage.getItem("selectedIncident"));
        assignedCountermeasures = getIncidentCountermeasures(selectedIncident);
        let availableCountermeasuresTable = document.getElementById("availableCountermeasures");
        clearTable(availableCountermeasuresTable);
        let assignedCountermeasuresTable = document.getElementById("assignedCountermeasures");
        clearTable(assignedCountermeasuresTable);
        countermeasures.forEach(cm => {
            let row;
            if (assignedCountermeasures.includes(cm)) {
                row = assignedCountermeasuresTable.insertRow();
                row.setAttribute("onclick", "selectAssignedCountermeasure(this)");
            }
            else {
                row = availableCountermeasuresTable.insertRow();
                row.setAttribute("onclick", "selectAvailableCountermeasure(this)");
            }
            row.setAttribute("class", "unhighlighted");
            row.setAttribute("data-value", cm.id);
            let name = row.insertCell(0);
            name.innerHTML = cm.name;
            let description = row.insertCell(1);
            description.innerHTML = cm.description;
        });
    }
    else {
        if (confirm("No Detrimental Event was selected.")) {
            window.history.back(); //in case there was a problem
        }
    }
});

/**
 * Returns an array containing the assigned mitigation actions ids of the incident.
 * @param {*} incident 
 * @returns {Array} assignedMitigationActions
 */
function getIncidentCountermeasures(incident) {
    let countermeasuresIds = [];
    let incidentCountermeasures = [];
    if (String(typeof incident.id_countermeasure) == "number") {
        incidentCountermeasures.push(incident.id_countermeasure);
    }
    else if (incident.id_countermeasure.length != 0) {
        incidentCountermeasures = incident.id_countermeasure.split(",").map(x => +x);
    }
    else {
        return [];
    }
    countermeasures.forEach(countermeasure => {
        if (incidentCountermeasures.includes(countermeasure.id)) {
            countermeasuresIds.push(countermeasure);
        }
    });
    return countermeasuresIds;
}

var availableCountermeasureSelected = false, availableCountermeasureId = 0;

function selectAvailableCountermeasure(row) {
    let assignedCountermeasuresTable = document.getElementById("assignedCountermeasures").rows;
    for (let cm of assignedCountermeasuresTable) {
        cm.className = "unhighlighted";
    }
    assignedCountermeasureSelected = false;
    assignedCountermeasureId = 0;
    let availableCountermeasuresTable = document.getElementById("availableCountermeasures").rows;
    for (let cm of availableCountermeasuresTable) {
        if (cm != row) {
            cm.className = "unhighlighted";
        }
    }
    row.className = row.className == "unhighlighted" ? "highlighted" : "unhighlighted";
    availableCountermeasureSelected = row.className == "highlighted";
    availableCountermeasureId = Number.parseInt(row.getAttribute("data-value"));
}

var assignedCountermeasureSelected = false, assignedCountermeasureId = 0;

function selectAssignedCountermeasure(row) {
    let availableCountermeasuresTable = document.getElementById("availableCountermeasures").rows;
    for (let cm of availableCountermeasuresTable) {
        cm.className = "unhighlighted";
    }
    availableCountermeasureSelected = false;
    availableCountermeasureId = 0;
    let assignedCountermeasuresTable = document.getElementById("assignedCountermeasures").rows;
    for (let cm of assignedCountermeasuresTable) {
        if (cm != row) {
            cm.className = "unhighlighted";
        }
    }
    row.className = row.className == "unhighlighted" ? "highlighted" : "unhighlighted";
    assignedCountermeasureSelected = row.className == "highlighted";
    assignedCountermeasureId = Number.parseInt(row.getAttribute("data-value"));
}

function assignCountermeasure() {
    if (!availableCountermeasureSelected) {
        alert("Please select a mitigation action.");
    }
    else {
        let countermeasuresIds = [];
        if (String(typeof selectedIncident.id_countermeasure) == "number") {
            countermeasuresIds.push(selectedIncident.id_countermeasure);
        }
        else if (selectedIncident.id_countermeasure.length != 0) {
            countermeasuresIds = selectedIncident.id_countermeasure.split(",").map(x => +x);
        }
        countermeasuresIds.push(availableCountermeasureId);
        selectedIncident.id_countermeasure = countermeasuresIds.join(", ");
        incidents.forEach((incident, index) => {
            if (incident.id == selectedIncident.id) {
                incidents[index] = selectedIncident;
                RORIObject.incidents = incidents;
                sessionStorage.setItem("selectedIncident", JSON.stringify(selectedIncident));
                localStorage.setItem("RORIString", JSON.stringify(RORIObject));
                window.location.reload();
            }
        });
    }
}

function removeCountermeasure() {
    if (!assignedCountermeasureSelected) {
        alert("Please select an assigned mitigation action.");
    }
    else {
        let incidentCountermeasures = getIncidentCountermeasures(selectedIncident).map(x => x.id);
        incidentCountermeasures.forEach((id, index) => {
            if (id == assignedCountermeasureId) {
                incidentCountermeasures.splice(index, 1);
                selectedIncident.id_countermeasure = incidentCountermeasures.join(", ");
            }
        });
        incidents.forEach((incident, index) => {
            if (incident.id == selectedIncident.id) {
                incidents[index] = selectedIncident;
                RORIObject.incidents = incidents;
                sessionStorage.setItem("selectedIncident", JSON.stringify(selectedIncident));
                localStorage.setItem("RORIString", JSON.stringify(RORIObject));
                window.location.reload();
            }
        });
    }
}