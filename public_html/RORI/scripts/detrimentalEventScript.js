var RORIObject;
var organizations = [], equipment = [], countermeasures = [], risk_mitigations = [], annual_response_mitigations = [], annual_response_costs = [], incidents = [], annual_loss_expectancies = [];

document.addEventListener("DOMContentLoaded", function () {
    if (localStorage.getItem("RORIString")) {
        RORIObject = JSON.parse(localStorage.getItem("RORIString"));
        extract();
    }
    else {
        RORIObject = {};
    }
    let incidentsTable = document.getElementById("incidentsTable");
    incidents.forEach(incident => {
        let row = incidentsTable.insertRow();
        row.setAttribute("class", "unhighlighted");
        row.setAttribute("onclick", "selectIncident(this)");
        row.setAttribute("data-value", incident.id);
        let name = row.insertCell(0);
        name.innerHTML = incident.name;
        let description = row.insertCell(1);
        description.innerHTML = incident.description;
        let riskLevel = row.insertCell(2);
        riskLevel.innerHTML = incident.risk_level;
        let ama = row.insertCell(3);
        ama.innerHTML = getIncidentCountermeasures(incident);
    });
});

/**
 * Returns a String representation of the incident's assigned mitigation actions.
 * @param {*} incident 
 * @returns {String} assignedMitigationActions
 */
function getIncidentCountermeasures(incident) {
    let ama = ""; //assigned mitigation action
    let countermeasuresNames = [];
    let incidentCountermeasures = [];
    if (String(typeof incident.id_countermeasure) == "number") {
        incidentCountermeasures.push(incident.id_countermeasure);
    }
    else if (incident.id_countermeasure.length != 0) {
        incidentCountermeasures = incident.id_countermeasure.split(",").map(x => +x);
    }
    else {
        return "";
    }
    countermeasures.forEach(countermeasure => {
        if (incidentCountermeasures.includes(countermeasure.id)) {
            countermeasuresNames.push(countermeasure.name);
        }
    });
    ama = countermeasuresNames.join(", ");
    return ama;
}

/**
 * When the user clicks on the add button, open the modal.
 */
function openAddIncidentForm() {
    document.getElementById("addModal").style.display = "block";
    document.getElementById("addName").value = "";
    document.getElementById("addDescription").value = "";
}

/**
 * Adds a new incident with the provided values in the form.
 * @param {*} form 
 */
function addIncident(form) {
    incidents.push({
        id: getNewIncidentId(),
        name: form[0].value,
        description: form[1].value,
        risk_level: "",
        id_countermeasure: "",
        id_organization: "",
        id_ale: "",
    });
    RORIObject.incidents = incidents;
    localStorage.setItem("RORIString", JSON.stringify(RORIObject));
    closeDialog();
    window.location.reload();
}

/**
 * When trying to add a new incident, this function sets an id for it.
 * @returns {number} New Incident ID
 */
function getNewIncidentId() {
    let id = 1;
    incidents.forEach(incident => {
        if (incident.id >= id) {
            id = incident.id + 1;
        }
    });
    return id;
}

var incidentSelected = false;
var selectedIncidentId;
/**
 * Highlights the incidents table's selected row.
 * @param {*} row 
 */
function selectIncident(row) {
    let incidentsRows = document.getElementById("incidentsTable").rows;
    for (let incident of incidentsRows) {
        if (incident != row) {
            incident.className = "unhighlighted";
        }
    }
    row.className = row.className == "unhighlighted" ? "highlighted" : "unhighlighted"; //toggle row highlight in case it was selected
    incidentSelected = row.className == "highlighted";
    selectedIncidentId = Number.parseInt(row.getAttribute("data-value"));
}

/**
 * When the user clicks on the edit button, open the modal.
 */
function openEditIncidentForm() {
    if (incidentSelected) {
        let editModal = document.getElementById("editModal");
        editModal.style.display = "block";
        incidents.forEach(incident => {
            if (incident.id == selectedIncidentId) {
                document.getElementById("editName").value = incident.name;
                document.getElementById("editDescription").value = incident.description;
                // document.getElementById("editRiskLevel").value = incident.risk_level;
            }
        });
    }
    else {
        alert("Please select a detrimental event.");
    }
}

/**
 * Updates an incident with the provided values in the form.
 * @param {*} form 
 */
function editIncident(form) {
    incidents.forEach(incident => {
        if (incident.id == selectedIncidentId) {
            incident.name = form[0].value;
            incident.description = form[1].value;
            // incident.risk_level = form[2].value;
        }
    });
    RORIObject.incidents = incidents;
    localStorage.setItem("RORIString", JSON.stringify(RORIObject));
    closeDialog();
    window.location.reload();
}

function openDeleteIncidentForm() {
    if (incidentSelected) {
        let deleteModal = document.getElementById("deleteModal");
        deleteModal.style.display = "block";
        incidents.forEach(incident => {
            if (incident.id == selectedIncidentId) {
                document.getElementById("deleteName").innerHTML = 'Proceed with deleting "' + incident.name + '" detrimental event?';
            }
        });
    }
    else {
        alert("Please select an detrimental event.");
    }
}

function deleteIncident() {
    let aleId;
    incidents.forEach(incident => {
        if (incident.id == selectedIncidentId) {
            aleId = incident.id_ale;
        }
    });
    if (aleId) {
        alert("Cannot deleted the selected detrimental event.\nPlease remove its associated annual loss expectancy.");
        return;

    }
    let index = 0;
    incidents.forEach(incident => {
        if (incident.id == selectedIncidentId) {
            index = incidents.indexOf(incident);
            incidents.splice(index, 1);
        }
    });
    RORIObject.incidents = incidents;
    localStorage.setItem("RORIString", JSON.stringify(RORIObject));
    closeDialog();
    window.location.reload();
}

function assignMitigationActionToIncident() {
    if (incidentSelected) {
        let selectedIncident;
        incidents.forEach(incident => {
            if (incident.id == selectedIncidentId) {
                selectedIncident = incident;
            }
        })
        sessionStorage.setItem("selectedIncident", JSON.stringify(selectedIncident));
        window.open("/RORI_tool/assignMitigationActionToIncident.html", "_self");
    }
    else {
        alert("Please select a Detrimental Event.");
    }
}

/**
 * When the user clicks on <span> (x), close the modal.
 */
function closeDialog() {
    document.getElementById("addModal").style.display = "none";
    document.getElementById("editModal").style.display = "none";
    document.getElementById("deleteModal").style.display = "none";
}