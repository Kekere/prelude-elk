var selectedOrganization, RORIObject;

document.addEventListener("DOMContentLoaded", function () {
    if (localStorage.getItem("RORIString")) {
        RORIObject = JSON.parse(localStorage.getItem("RORIString"));
        extract();
    }
    if (sessionStorage.getItem("selectedOrganization")) {
        selectedOrganization = JSON.parse(sessionStorage.getItem("selectedOrganization"));
        let organizationEquipment = [];
        if (String(typeof selectedOrganization.id_equipments) == "number") {
            organizationEquipment.push(selectedOrganization.id_equipments);
        }
        else if (selectedOrganization.id_equipments.length != 0) {
            organizationEquipment = selectedOrganization.id_equipments.split(",").map(Number);
        }
        let availableEquipment = document.getElementById("availableEquipment");
        clearTable(availableEquipment);
        let assignedEquipment = document.getElementById("assignedEquipment");
        clearTable(assignedEquipment);
        equipment.forEach(eq => {
            if (organizationEquipment.includes(eq.id)) {
                let row = assignedEquipment.insertRow();
                row.setAttribute("class", "unhighlighted");
                row.setAttribute("data-value", eq.id);
                row.setAttribute("onclick", "selectAssignedEquipment(this)");
                let name = row.insertCell(0);
                name.innerHTML = eq.name;
                let type = row.insertCell(1);
                type.innerHTML = eq.type;
            }
            else {
                let row = availableEquipment.insertRow();
                row.setAttribute("class", "unhighlighted");
                row.setAttribute("data-value", eq.id);
                row.setAttribute("onclick", "selectAvailableEquipment(this)");
                let name = row.insertCell(0);
                name.innerHTML = eq.name;
                let type = row.insertCell(1);
                type.innerHTML = eq.type;
            }
        });
    }
    else {
        if (confirm("No organization was selected.")) {
            window.history.back(); //in case there was a problem while fetching the organization id, go back to organizations page
        }
    }
});

var availableEquipmentSelected = false, availableEquipmentId = 0;

function selectAvailableEquipment(row) {
    let assignedEquipment = document.getElementById("assignedEquipment").rows;
    for (let eq of assignedEquipment) {
        eq.className = "unhighlighted";
    }
    assignedEquipmentSelected = false;
    assignedEquipmentId = 0;
    let availableEquipment = document.getElementById("availableEquipment").rows;
    for (let eq of availableEquipment) {
        if (eq != row) {
            eq.className = "unhighlighted";
        }
    }
    row.className = row.className == "unhighlighted" ? "highlighted" : "unhighlighted";
    availableEquipmentSelected = row.className == "highlighted";
    availableEquipmentId = Number.parseInt(row.getAttribute("data-value"));
}

var assignedEquipmentSelected = false, assignedEquipmentId = 0;

function selectAssignedEquipment(row) {
    let availableEquipment = document.getElementById("availableEquipment").rows;
    for (let eq of availableEquipment) {
        eq.className = "unhighlighted";
    }
    availableEquipmentSelected = false;
    availableEquipmentId = 0;
    let assignedEquipment = document.getElementById("assignedEquipment").rows;
    for (let eq of assignedEquipment) {
        if (eq != row) {
            eq.className = "unhighlighted";
        }
    }
    row.className = row.className == "unhighlighted" ? "highlighted" : "unhighlighted";
    assignedEquipmentSelected = row.className == "highlighted";
    assignedEquipmentId = Number.parseInt(row.getAttribute("data-value"));
    if (assignedEquipmentSelected) {
        selectedOrganization.AEV.forEach(aiv => {
            if (aiv.equipmentId == assignedEquipmentId) {
                document.getElementById("ec").value = aiv.ec ? aiv.ec : "0.00";
                document.getElementById("sc").value = aiv.sc ? aiv.sc : "0.00";
                document.getElementById("pc").value = aiv.pc ? aiv.pc : "0.00";
                document.getElementById("rv").value = aiv.rv ? aiv.rv : "0.00";
                document.getElementById("oc").value = aiv.oc ? aiv.oc : "0.00";
                document.getElementById("nop").value = aiv.nop ? aiv.nop : "0";
                document.getElementById("totalValue").value = aiv.AEV;
            }
        });
    }
    else {
        document.getElementById("totalValue").value = 0;
    }
}

function assignPEP() {
    if (!(availableEquipmentSelected || assignedEquipmentSelected)) {
        if (confirm("Please select a PEP.")) {
            return;
        }
    }
    let totalValue = document.getElementById("totalValue");
    if (totalValue.valueAsNumber <= 0) {
        alert("Total value should be greater than 0.");
    }
    else {
        let AIV;
        let totalChecked = document.getElementById("giveTotal").checked;
        let ec = document.getElementById("ec");
        let sc = document.getElementById("sc");
        let pc = document.getElementById("pc");
        let rv = document.getElementById("rv");
        let oc = document.getElementById("oc");
        let nop = document.getElementById("nop");
        if (availableEquipmentId != 0) {
            AIV = {
                equipmentId: availableEquipmentId,
                organizationId: selectedOrganization.id,
                AEV: totalValue.valueAsNumber,
                ec: totalChecked ? 0.00 : ec.valueAsNumber,
                sc: totalChecked ? 0.00 : sc.valueAsNumber,
                pc: totalChecked ? 0.00 : pc.valueAsNumber,
                rv: totalChecked ? 0.00 : rv.valueAsNumber,
                oc: totalChecked ? 0.00 : oc.valueAsNumber,
                nop: totalChecked ? 0.00 : nop.valueAsNumber,
            };

        }
        else if (assignedEquipmentId != 0) {
            AIV = {
                equipmentId: assignedEquipmentId,
                organizationId: selectedOrganization.id,
                AEV: totalValue.valueAsNumber,
                ec: totalChecked ? 0.00 : ec.valueAsNumber,
                sc: totalChecked ? 0.00 : sc.valueAsNumber,
                pc: totalChecked ? 0.00 : pc.valueAsNumber,
                rv: totalChecked ? 0.00 : rv.valueAsNumber,
                oc: totalChecked ? 0.00 : oc.valueAsNumber,
                nop: totalChecked ? 0.00 : nop.valueAsNumber,
            }
        }
        if (AIV) {
            if (assignedEquipmentId != 0) {
                selectedOrganization.AEV.forEach((aiv, index) => {
                    if (aiv.equipmentId == assignedEquipmentId) {
                        selectedOrganization.AEV[index] = AIV;
                    }
                });
            }
            else {
                let organizationEquipment = [];
                if (String(typeof selectedOrganization.id_equipments) == "number") {
                    organizationEquipment.push(selectedOrganization.id_equipments);
                }
                else if (selectedOrganization.id_equipments.length != 0) {
                    organizationEquipment = selectedOrganization.id_equipments.split(",").map(Number);
                }
                organizationEquipment.push(availableEquipmentId);
                selectedOrganization.id_equipments = organizationEquipment.join(", ");
                selectedOrganization.AEV.push(AIV);
            }
            updateOrganizations(selectedOrganization);
            RORIObject.organizations = organizations;
            let eqId = availableEquipmentId ? availableEquipmentId : assignedEquipmentId;
            equipment.forEach(eq => {
                if (eq.id == eqId) {
                    eq.AEV = AIV.AEV;
                }
            });
            RORIObject.equipment = equipment;
            sessionStorage.setItem("selectedOrganization", JSON.stringify(selectedOrganization));
            localStorage.setItem("RORIString", JSON.stringify(RORIObject));
            window.location.reload();
        }
    }
}

function toggleTotal() {
    let totalChecked = document.getElementById("giveTotal").checked;
    let formElements = document.getElementById("aevForm").elements;
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
    let ec = document.getElementById("ec").valueAsNumber ? document.getElementById("ec").valueAsNumber : 0;
    let sc = document.getElementById("sc").valueAsNumber ? document.getElementById("sc").valueAsNumber : 0;
    let pc = document.getElementById("pc").valueAsNumber ? document.getElementById("pc").valueAsNumber : 0;
    let rv = document.getElementById("rv").valueAsNumber ? document.getElementById("rv").valueAsNumber : 0;
    let oc = document.getElementById("oc").valueAsNumber ? document.getElementById("oc").valueAsNumber : 0;
    let nop = document.getElementById("nop").valueAsNumber ? document.getElementById("nop").valueAsNumber : 0;
    let aiv = Math.m(Math.s(Math.a(Math.a(Math.a(ec, pc), sc), oc), rv), nop);
    totalValue.value = aiv;
}

function removePEP() {
    if (!assignedEquipmentSelected) {
        alert("Please select a PEP");
    }
    else {
        selectedOrganization.AEV.forEach(aiv => {
            if (aiv.equipmentId == assignedEquipmentId) {
                let index = selectedOrganization.AEV.indexOf(aiv);
                selectedOrganization.AEV.splice(index, 1);
            }
        });
        let id_equipments = [];
        selectedOrganization.AEV.map(aiv => id_equipments.push(aiv.equipmentId));
        selectedOrganization.id_equipments = id_equipments.sort((a, b) => a - b).join(", ");
        updateOrganizations(selectedOrganization);
        RORIObject.organizations = organizations;
        sessionStorage.setItem("selectedOrganization", JSON.stringify(selectedOrganization));
        localStorage.setItem("RORIString", JSON.stringify(RORIObject));
        window.location.reload();
    }
}

function updateOrganizations(organization) {
    organizations.forEach((org, index) => {
        if (org.id == organization.id) {
            organizations[index] = organization;
        }
    });
}