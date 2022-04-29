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
    sessionStorage.clear();
    let organizationTable = document.getElementById("organizationsTable");
    organizations.forEach(organization => {
        let row = organizationTable.insertRow();
        row.setAttribute("class", "unhighlighted");
        row.setAttribute("onclick", "selectOrganization(this)");
        row.setAttribute("data-value", organization.id);
        let name = row.insertCell(0);
        name.innerHTML = organization.name;
        let description = row.insertCell(1);
        description.innerHTML = organization.description;
        let aiv = row.insertCell(2);
        aiv.innerHTML = getAIV(organization);
    });
});

/**
 * Calculates the organization's AIV.
 * @param {*} organization 
 * @returns {number} AIV.
 */
function getAIV(organization) {
    let aiv = 0;
    organization.AEV.forEach(aev => {
        aiv += aev.AEV;
    });
    return aiv;
}

/**
 * When the user clicks on the add button, open the modal.
 */
function openAddOrganizationForm() {
    document.getElementById("addModal").style.display = "block";
    document.getElementById("addName").value = "";
    document.getElementById("addDescription").value = "";
}

/**
 * Adds a new organization with the provided values in the form.
 * @param {*} form 
 */
function addOrganization(form) {
    organizations.push({
        id: getNewOrganizationId(),
        name: form[0].value,
        description: form[1].value,
        id_equipments: "",
        AEV: [],
        xpath: "xpath",
    });
    RORIObject.organizations = organizations;
    localStorage.setItem("RORIString", JSON.stringify(RORIObject));
    closeDialog();
    window.location.reload();
}

/**
 * When trying to add a new organization, this function sets an id for it.
 * @returns {number} New Organization ID.
 */
function getNewOrganizationId() {
    let id = 1;
    organizations.forEach(organization => {
        if (organization.id >= id) {
            id = organization.id + 1;
        }
    });
    return id;
}

var organizationSelected = false;
var selectedOrganizationId;
/**
 * Highlights the organizations table's selected row.
 * @param {*} row 
 */
function selectOrganization(row) {
    let organizationsRows = document.getElementById("organizationsTable").rows;
    for (let org of organizationsRows) {
        if (org != row) {
            org.className = "unhighlighted";
        }
    }
    row.className = row.className == "unhighlighted" ? "highlighted" : "unhighlighted"; //toggle row highlight in case it was selected
    organizationSelected = row.className == "highlighted";
    selectedOrganizationId = Number.parseInt(row.getAttribute("data-value"));
}

/**
 * When the user clicks on the edit button, open the modal.
 */
function openEditOrganizationForm() {
    if (organizationSelected) {
        let editModal = document.getElementById("editModal");
        editModal.style.display = "block";
        organizations.forEach(organization => {
            if (organization.id == selectedOrganizationId) {
                document.getElementById("editName").value = organization.name;
                document.getElementById("editDescription").value = organization.description;
            }
        });
    }
    else {
        alert("Please select an organization.");
    }
}

/**
 * Updates an organization with the provided values in the form.
 * @param {*} form 
 */
function editOrganization(form) {
    organizations.forEach(organization => {
        if (organization.id == selectedOrganizationId) {
            organization.description = form[1].value;
            organization.name = form[0].value;
        }
    });
    RORIObject.organizations = organizations;
    localStorage.setItem("RORIString", JSON.stringify(RORIObject));
    closeDialog();
    window.location.reload();
}

/**
 * When the user clicks on the delete button, open the modal.
 */
function openDeleteOrganizationForm() {
    if (organizationSelected) {
        let deleteModal = document.getElementById("deleteModal");
        deleteModal.style.display = "block";
        organizations.forEach(organization => {
            if (organization.id == selectedOrganizationId) {
                document.getElementById("deleteName").innerHTML = 'Proceed with deleting "' + organization.name + '" organization?';
            }
        });
    }
    else {
        alert("Please select an organization.");
    }
}

/**
 * Deletes the selected organization.
 */
function deleteOrganization() {
    let forbidden = false;
    incidents.forEach(incident => {
        if (incident.id_organization == selectedOrganizationId) {
            forbidden = true;
        }
    });
    if (forbidden) {
        alert("Cannot delete the selected organization.\nPlease remove any associated detrimental events.");
        closeDialog();
        return;
    }
    let index = 0;
    organizations.forEach(organization => {
        if (organization.id == selectedOrganizationId) {
            index = organizations.indexOf(organization);
            organizations.splice(index, 1);
        }
    });
    RORIObject.organizations = organizations;
    localStorage.setItem("RORIString", JSON.stringify(RORIObject));
    closeDialog();
    window.location.reload();
}

function assignEquipment() {
    if (organizationSelected) {
        let selectedOrganization = getOrganizationById(selectedOrganizationId);
        sessionStorage.setItem("selectedOrganization", JSON.stringify(selectedOrganization));
        window.open("/RORI_tool/assignPEP.html", "_self");
    }
    else {
        alert("Please select an organization.");
    }
}

function assignIncident() {
    if (organizationSelected) {
        let selectedOrganization = getOrganizationById(selectedOrganizationId);
        sessionStorage.setItem("selectedOrganization", JSON.stringify(selectedOrganization));
        window.open("/RORI_tool/assignIncident.html", "_self");
    }
    else {
        alert("Please select an organization.");
    }
}

function getOrganizationById(organizationId) {
    let selectedOrganization;
    organizations.forEach(organization => {
        if (organization.id == organizationId) {
            selectedOrganization = organization;
        }
    });
    return selectedOrganization;
}

/**
 * When the user clicks on the close button "x", close the modal.
 */
function closeDialog() {
    document.getElementById("addModal").style.display = "none";
    document.getElementById("editModal").style.display = "none";
    document.getElementById("deleteModal").style.display = "none";
}