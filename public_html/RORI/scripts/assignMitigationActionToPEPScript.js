var selectedEquipment, RORIObject;

document.addEventListener("DOMContentLoaded", function () {
    if (localStorage.getItem("RORIString")) {
        RORIObject = JSON.parse(localStorage.getItem("RORIString"));
        extract();
    }
    if (sessionStorage.getItem("selectedEquipment")) {
        selectedEquipment = JSON.parse(sessionStorage.getItem("selectedEquipment"));
        let equipmentCms = [];
        let availableCountermeasures = [];
        countermeasures.forEach(countermeasure => {
            if (countermeasure.id_equipment == selectedEquipment.id) {
                equipmentCms.push(countermeasure);
            }
            else {
                if (countermeasure.id_equipment == "") {
                    availableCountermeasures.push(countermeasure);
                }
            }
        });
        let availableCountermeasruesTable = document.getElementById("availableCountermeasures");
        clearTable(availableCountermeasruesTable);
        let assignedEquipmentTable = document.getElementById("assignedCountermeasures");
        clearTable(assignedEquipmentTable);
        availableCountermeasures.forEach(cm => {
            let row = availableCountermeasruesTable.insertRow();
            row.setAttribute("class", "unhighlighted");
            row.setAttribute("data-value", cm.id);
            row.setAttribute("onclick", "selectAvailableCountermeasure(this)");
            let name = row.insertCell(0);
            name.innerHTML = cm.name;
            let description = row.insertCell(1);
            description.innerHTML = cm.description;
        });
        equipmentCms.forEach(cm => {
            let row = assignedEquipmentTable.insertRow();
            row.setAttribute("class", "unhighlighted");
            row.setAttribute("data-value", cm.id);
            row.setAttribute("onclick", "selectAssignedCountermeasure(this)");
            let name = row.insertCell(0);
            name.innerHTML = cm.name;
            let description = row.insertCell(1);
            description.innerHTML = cm.description;
        });
    }
    else {
        if (confirm("No PEP was selected.")) {
            window.history.back(); //in case there was a problem
        }
    }
});

/**
 * Returns the risk mitigation percentage of the countermeasure.
 * @param {*} countermeasure 
 * @returns {number} countermeasure risk mitigation percentage.
 */
function getRM(countermeasure) {
    let rmValue = 0;
    risk_mitigations.forEach(rm => {
        if (rm.id == countermeasure.id_rm) {
            if ((rm.EF && rm.EF != "") && (rm.COV && rm.COV != "")) {
                rmValue = rm.EF * rm.COV;
            }
            else {
                rmValue = rm.RM;
            }
        }
    });
    return rmValue;
}

var availableCountermeasureSelected = false, availableCountermeasureId = 0;

function selectAvailableCountermeasure(row) {
    let assignedCountermeasures = document.getElementById("assignedCountermeasures").rows;
    for (let cm of assignedCountermeasures) {
        cm.className = "unhighlighted";
    }
    assignedCountermeasureSelected = false;
    assignedCountermeasureId = 0;
    let availableCountermeasures = document.getElementById("availableCountermeasures").rows;
    for (let cm of availableCountermeasures) {
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
    let availableCountermeasures = document.getElementById("availableCountermeasures").rows;
    for (let cm of availableCountermeasures) {
        cm.className = "unhighlighted";
    }
    availableCountermeasureSelected = false;
    availableCountermeasureId = 0;
    let assignedCountermeasures = document.getElementById("assignedCountermeasures").rows;
    for (let cm of assignedCountermeasures) {
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
        countermeasures.forEach((cm, index) => {
            if (cm.id == availableCountermeasureId) {
                cm.id_equipment = selectedEquipment.id;
                countermeasures[index] = cm;
                RORIObject.countermeasures = countermeasures;
                localStorage.setItem("RORIString", JSON.stringify(RORIObject));
                window.location.reload();
            }
        });
    }
}

function removeCountermeasure() {
    if (!assignedCountermeasureSelected) {
        alert("Plesae select an assigned mitigation action");
    }
    else {
        countermeasures.forEach((cm, index) => {
            if (cm.id == assignedCountermeasureId) {
                cm.id_equipment = "";
                countermeasures[index] = cm;
                RORIObject.countermeasures = countermeasures;
                localStorage.setItem("RORIString", JSON.stringify(RORIObject));
                window.location.reload();
            }
        });
    }
}