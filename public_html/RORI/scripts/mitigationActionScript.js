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
    let countermeasuresTable = document.getElementById("countermeasuresTable");
    countermeasures.forEach(countermeasure => {
        let row = countermeasuresTable.insertRow();
        row.setAttribute("class", "unhighlighted");
        row.setAttribute("onclick", "selectCountermeasure(this)");
        row.setAttribute("data-value", countermeasure.id);
        let name = row.insertCell(0);
        name.innerHTML = countermeasure.name;
        let description = row.insertCell(1);
        description.innerHTML = countermeasure.description;
        let rm = row.insertCell(2);
        rm.innerHTML = getRM(countermeasure).toFixed(4); //get rm
        let arc = row.insertCell(3);
        arc.innerHTML = getARC(countermeasure).toFixed(2); //get arc
        let restrictions = row.insertCell(4);
        restrictions.innerHTML = getRestrictions(countermeasure); //get restrictions
    });
});

/**
 * Returns the risk mitigation percentage of the countermeasure.
 * @param {*} countermeasure 
 * @returns {number} countermeasure risk mitigation percentage.
 */
function getRM(countermeasure) {
    let rmPercent = 0;
    risk_mitigations.forEach(rm => {
        if (rm.id == countermeasure.id_rm) {
            if ((rm.EF && rm.EF != "") && (rm.COV && rm.COV != "")) {
                rmPercent = rm.EF * rm.COV * 100;
            }
            else {
                rmPercent = rm.RM * 100;
            }
        }
    });
    return rmPercent;
}

/**
 * Returns the annual response cost of the countermeasure.
 * @param {*} countermeasure 
 * @returns {number} Countermeasure annual response cost.
 */
function getARC(countermeasure) {
    let countermeasureARC = 0;
    annual_response_costs.forEach(arc => {
        if (arc.id == countermeasure.id_arc) {
            countermeasureARC = arc.total != "" ? arc.total : Math.a(arc.COI, Math.a(arc.COM, Math.a(arc.ODC, arc.IC)));
        }
    });
    return countermeasureARC;
}

function getRestrictions(countermeasure) {
    let restrictionsIds = [];
    let restrictions = [];
    if (String(typeof countermeasure.restriction) == "number") {
        restrictionsIds.push(countermeasure.restriction);
    } else if (countermeasure.restriction.length != 0) {
        restrictionsIds = countermeasure.restriction.split(",").map(Number);
    } else {
        return "";
    }
    countermeasures.forEach(cm => {
        if (restrictionsIds.includes(cm.id)) {
            restrictions.push(cm.name);
        }
    });
    return restrictions.join(", ");
}

/**
 * When the user clicks on the add button, open the modal.
 */
function openAddCountermeasureForm() {
    document.getElementById("addModal").style.display = "block";
    document.getElementById("addName").value = "";
    document.getElementById("addDescription").value = "";
    document.getElementById("addTotallyRestrictive").value = "no";
}

/**
 * Adds a new countermeasure with the provided values in the form.
 * @param {*} form 
 */
function addCountermeasure(form) {
    countermeasures.push({
        id: getNewCountermeasureId(),
        name: form[0].value,
        description: form[1].value,
        totally_restrictive: form[2].value,
        restriction: "",
        id_equipment: "",
        id_rm: "",
        id_arc: "",
        xpath: "xpath",
    });
    RORIObject.countermeasures = countermeasures;
    localStorage.setItem("RORIString", JSON.stringify(RORIObject));
    closeDialog();
    window.location.reload();
}

/**
 * When trying to add a new countermeasure, this function sets an id for it.
 * @returns {number} New Countermeasure ID.
 */
function getNewCountermeasureId() {
    let id = 1;
    countermeasures.forEach(countermeasure => {
        if (countermeasure.id >= id) {
            id = countermeasure.id + 1;
        }
    });
    return id;
}

var countermeasureSelected = false;
var selectedCountermeasureId;
/**
 * Highlights the countermeasures table's selected row.
 * @param {*} row 
 */
function selectCountermeasure(row) {
    let countermeasuresRows = document.getElementById("countermeasuresTable").rows;
    for (let cm of countermeasuresRows) {
        if (cm != row) {
            cm.className = "unhighlighted";
        }
    }
    row.className = row.className == "unhighlighted" ? "highlighted" : "unhighlighted"; //toggle row highlight in case it was selected
    countermeasureSelected = row.className == "highlighted";
    selectedCountermeasureId = Number.parseInt(row.getAttribute("data-value"));
}

/**
 * When the user clicks on the edit button, open the modal.
 */
function openEditCountermeasureForm() {
    if (countermeasureSelected) {
        let editModal = document.getElementById("editModal");
        editModal.style.display = "block";
        countermeasures.forEach(countermeasure => {
            if (countermeasure.id == selectedCountermeasureId) {
                document.getElementById("editName").value = countermeasure.name;
                document.getElementById("editDescription").value = countermeasure.description;
                document.getElementById("editTotallyRestrictive").value = countermeasure.totally_restrictive;
            }
        });
    } else {
        alert("Please select a mitigation action.");
    }
}

/**
 * Updates an countermeasure with the provided values in the form.
 * @param {*} form 
 */
function editCountermeasure(form) {
    countermeasures.forEach(countermeasure => {
        if (countermeasure.id == selectedCountermeasureId) {
            countermeasure.name = form[0].value;
            countermeasure.description = form[1].value;
            countermeasure.totally_restrictive = form[2].value;
        }
    });
    RORIObject.countermeasures = countermeasures;
    localStorage.setItem("RORIString", JSON.stringify(RORIObject));
    closeDialog();
    window.location.reload();
}

function openDeleteCountermeasureForm() {
    if (countermeasureSelected) {
        let deleteModal = document.getElementById("deleteModal");
        deleteModal.style.display = "block";
        countermeasures.forEach(countermeasure => {
            if (countermeasure.id == selectedCountermeasureId) {
                document.getElementById("deleteName").innerHTML = 'Proceed with deleting "' + countermeasure.name + '" mitigation action?';
            }
        });
    } else {
        alert("Please select a mitigation action.");
    }
}

function deleteCountermeasure(form) {
    let forbidden = false;
    countermeasures.forEach(countermeasure => {
        if (countermeasure.id == selectedCountermeasureId) {
            if (countermeasure.restriction || countermeasure.id_equipment || countermeasure.id_rm || countermeasure.id_arc) {
                forbidden = true;
            }
        }
    });
    if (forbidden) {
        alert("Cannot delete the selected mitigation action.\nPlease remove any associated restrictions, countermeasure, risk mitigation value and/or annual response cost value.");
        closeDialog();
        return;
    }
    let index = 0;
    countermeasures.forEach(countermeasure => {
        if (countermeasure.id == selectedCountermeasureId) {
            index = countermeasures.indexOf(countermeasure);
            countermeasures.splice(index, 1);
        }
    });
    RORIObject.countermeasures = countermeasures;
    localStorage.setItem("RORIString", JSON.stringify(RORIObject));
    closeDialog();
    window.location.reload();
}

function assignRM() {
    if (countermeasureSelected) {
        let selectedCountermeasure, assignedRM;
        selectedCountermeasure = getCountermeasureById(selectedCountermeasureId);
        risk_mitigations.forEach(rm => {
            if (rm.id == selectedCountermeasure.id_rm) {
                assignedRM = rm;
            }
        });
        if (assignedRM) {
            sessionStorage.setItem("assignedRM", JSON.stringify(assignedRM));
        }
        else {
            sessionStorage.clear();
        }
        sessionStorage.setItem("selectedCountermeasure", JSON.stringify(selectedCountermeasure));
        window.open("/RORI/assignRM.html", "_self");
    }
    else {
        alert("Please select a Mitigation Action.");
    }
}

function assignARC() {
    if (countermeasureSelected) {
        let selectedCountermeasure, assignedARC;
        selectedCountermeasure = getCountermeasureById(selectedCountermeasureId);
        annual_response_costs.forEach(arc => {
            if (arc.id == selectedCountermeasure.id_arc) {
                assignedARC = arc;
            }
        });
        if (assignedARC) {
            sessionStorage.setItem("assignedARC", JSON.stringify(assignedARC));
        }
        else {
            sessionStorage.clear();
        }
        sessionStorage.setItem("selectedCountermeasure", JSON.stringify(selectedCountermeasure));
        window.open("/RORI/assignARC.html", "_self");
    }
    else {
        alert("Please select a Mitigation Action.");
    }
}

function assignRestrictions() {
    if (countermeasureSelected) {
        let selectedCountermeasure = getCountermeasureById(selectedCountermeasureId);
        if (selectedCountermeasure.totally_restrictive == "yes") {
            alert("Mitigation Action is totally restrictive.");
            return;
        }
        sessionStorage.setItem("selectedCountermeasure", JSON.stringify(selectedCountermeasure));
        window.open("/RORI/assignRestrictions.html", "_self");
    }
    else {
        alert("Please select a Mitigation Action.");
    }
}

function getCountermeasureById(countermeasureId) {
    let countermeasure = {};
    countermeasures.forEach(cm => {
        if (cm.id == countermeasureId) {
            countermeasure = cm;
        }
    });
    return countermeasure;
}

/**
 * When the user clicks on <span> (x), close the modal.
 */
function closeDialog() {
    document.getElementById("addModal").style.display = "none";
    document.getElementById("editModal").style.display = "none";
    document.getElementById("deleteModal").style.display = "none";
}