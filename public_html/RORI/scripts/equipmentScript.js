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
    let equipmentTable = document.getElementById("equipmentTable");
    equipment.forEach(eq => {
        let row = equipmentTable.insertRow();
        row.setAttribute("class", "unhighlighted");
        row.setAttribute("onclick", "selectEquipment(this)");
        row.setAttribute("data-value", eq.id);
        let name = row.insertCell(0);
        name.innerHTML = eq.name;
        let type = row.insertCell(1);
        type.innerHTML = eq.type;
        let ama = row.insertCell(2); //assigned mitigation action
        ama.innerHTML = getEquipmentCountermeasures(eq);
    });
});

/**
 * Returns a String representation of the equipment's assigned mitigation actions.
 * @param {*} equipment 
 * @returns {String} assignedMitigationActions
 */
function getEquipmentCountermeasures(eq) {
    let ama = ""; //assigned mitigation action
    let countermeasuresNames = [];
    let temp = []; //in case a countermeasure has more than one equipment
    countermeasures.forEach(countermeasure => {
        if (typeof countermeasure.id_equipment == "number") {
            if (countermeasure.id_equipment == eq.id) {
                countermeasuresNames.push(countermeasure.name);
            }
        } else if (countermeasure.id_equipment.length != 0) {
            temp = countermeasure.id_equipment.split(",").map(Number);
            if (temp.includes(eq.id)) {
                countermeasuresNames.push(countermeasure.name);
            }
        }
    });
    ama = countermeasuresNames.join(", ");
    return ama;
}

/**
 * When the user clicks on the add button, open the Add modal.
 */
function openAddEquipmentForm() {
    document.getElementById("addModal").style.display = "block";
    document.getElementById("addName").value = "";
    document.getElementById("addType").value = "";
}

/**
 * Adds a new PEP with the provided values in the form.
 * @param {*} form 
 */
function addEquipment(form) {
    equipment.push({
        id: getNewEquipmentId(),
        name: form[0].value,
        type: form[1].value,
        AEV: "",
        xpath: "xpath",
    });
    RORIObject.equipment = equipment;
    localStorage.setItem("RORIString", JSON.stringify(RORIObject));
    closeDialog();
    window.location.reload();
}

/**
 * When trying to add a new PEP, this function sets an id for it.
 * @returns {Number} New Equipment ID
 */
function getNewEquipmentId() {
    let id = 1;
    equipment.forEach(eq => {
        if (eq.id >= id) {
            id = eq.id + 1;
        }
    });
    return id;
}

var equipmentSelected = false;
var selectedEquipmentId;
/**
 * Highlights the equipment table's selected row.
 * @param {*} row 
 */
function selectEquipment(row) {
    let equipmentRows = document.getElementById("equipmentTable").rows;
    for (let eq of equipmentRows) {
        if (eq != row) {
            eq.className = "unhighlighted";
        }
    }
    row.className = row.className == "unhighlighted" ? "highlighted" : "unhighlighted"; //toggle row highlight in case it was selected
    equipmentSelected = row.className == "highlighted";
    selectedEquipmentId = Number.parseInt(row.getAttribute("data-value"));
}

/**
 * When the user clicks on the edit button, open the Edit modal.
 */
function openEditEquipmentForm() {
    if (equipmentSelected) {
        let editModal = document.getElementById("editModal");
        editModal.style.display = "block";
        equipment.forEach(eq => {
            if (eq.id == selectedEquipmentId) {
                document.getElementById("editName").value = eq.name;
                document.getElementById("editType").value = eq.type;
            }
        });
    }
    else {
        alert("Please select a PEP.");
    }
}

/**
 * Updates an equipment with the provided values in the form.
 * @param {*} form 
 */
function editEquipment(form) {
    equipment.forEach(eq => {
        if (eq.id == selectedEquipmentId) {
            eq.name = form[0].value;
            eq.type = form[1].value;
        }
    });
    RORIObject.equipment = equipment;
    localStorage.setItem("RORIString", JSON.stringify(RORIObject));
    closeDialog();
    window.location.reload();
}

function openDeleteEquipmentForm() {
    if (equipmentSelected) {
        let deleteModal = document.getElementById("deleteModal");
        deleteModal.style.display = "block";
        equipment.forEach(eq => {
            if (eq.id == selectedEquipmentId) {
                document.getElementById("deleteName").innerHTML = 'Proceed with deleting "' + eq.name + '" PEP?';
            }
        });
    }
    else {
        alert("Please select a PEP.");
    }
}

function deleteEquipment() {
    let forbidden = false;
    organizations.forEach(organization => {
        if (getOrganizationEquipmentIds(organization).includes(selectedEquipmentId)) {
            forbidden = true;
        }
    });
    countermeasures.forEach(countermeasure => {
        if (countermeasure.id_equipment == selectedEquipmentId) {
            forbidden = true;
        }
    });
    if (forbidden) {
        alert("Cannot delete the selected PEP.\nPlease remove the selected PEP from all organizations and any associated mitigation actions.");
        closeDialog();
        return;
    }
    let index = 0;
    equipment.forEach(eq => {
        if (eq.id == selectedEquipmentId) {
            index = equipment.indexOf(eq);
            equipment.splice(index, 1);
        }
    });
    RORIObject.equipment = equipment;
    localStorage.setItem("RORIString", JSON.stringify(RORIObject));
    closeDialog();
    window.location.reload();
}

function getOrganizationEquipmentIds(organization) {
    let organizationEquipmentIds = [];
    if (String(typeof organization.id_equipments) == "number") {
        organizationEquipment.push(organization.id_equipments);
    }
    else if (organization.id_equipments.length != 0) {
        organizationEquipmentIds = organization.id_equipments.split(",").map(Number);
    }
    else {
        return [];
    }
    return organizationEquipmentIds;
}

function assignMitigationActionToPEP() {
    if (equipmentSelected) {
        let selectedEquipment;
        equipment.forEach(eq => {
            if (eq.id == selectedEquipmentId) {
                selectedEquipment = eq;
            }
        })
        sessionStorage.setItem("selectedEquipment", JSON.stringify(selectedEquipment));
        window.open("/RORI_tool/assignMitigationActionToPEP.html", "_self");
    }
    else {
        alert("Please select a PEP.");
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