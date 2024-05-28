var selectedCountermeasure, assignedARC, RORIObject;

document.addEventListener("DOMContentLoaded", function () {
    if (localStorage.getItem("RORIString")) {
        RORIObject = JSON.parse(localStorage.getItem("RORIString"));
        extract();
    }
    if (sessionStorage.getItem("selectedCountermeasure")) {
        selectedCountermeasure = JSON.parse(sessionStorage.getItem("selectedCountermeasure"));
        if (sessionStorage.getItem("assignedARC")) {
            assignedARC = JSON.parse(sessionStorage.getItem("assignedARC"));
            if (assignedARC) {
                if (assignedARC.total) {
                    document.getElementById("totalValue").value = String(assignedARC.total)
                }
                else {
                    document.getElementById("coi").value = String(assignedARC.COI);
                    document.getElementById("com").value = String(assignedARC.COM);
                    document.getElementById("odc").value = String(assignedARC.ODC);
                    document.getElementById("ic").value = String(assignedARC.IC);
                    document.getElementById("totalValue").value = Math.a(assignedARC.COI, Math.a(assignedARC.COM, Math.a(assignedARC.ODC, assignedARC.IC)));
                }
            }
        }
    }
    else {
        if (confirm("No Mitigation Action was selected.")) {
            window.history.back(); //in case there was a problem
        }
    }
});

function assignARC() {
    let coi = document.getElementById("coi").valueAsNumber ? document.getElementById("coi").valueAsNumber : 0;
    let com = document.getElementById("com").valueAsNumber ? document.getElementById("com").valueAsNumber : 0;
    let odc = document.getElementById("odc").valueAsNumber ? document.getElementById("odc").valueAsNumber : 0;
    let ic = document.getElementById("ic").valueAsNumber ? document.getElementById("ic").valueAsNumber : 0;
    let totalValue = document.getElementById("totalValue").valueAsNumber;
    let totalChecked = document.getElementById("giveTotal").checked;
    if (totalValue <= 0) {
        alert("Total value should be greater than 0.");
        return;
    }
    if (assignedARC) {
        if (totalChecked) {
            assignedARC.COI = "";
            assignedARC.COM = "";
            assignedARC.ODC = "";
            assignedARC.IC = "";
            assignedARC.total = totalValue;
        }
        else {
            assignedARC.COI = coi;
            assignedARC.COM = com;
            assignedARC.ODC = odc;
            assignedARC.IC = ic;
            assignedARC.total = "";
        }
        annual_response_costs.forEach((arc, index) => {
            if (arc.id == assignedARC.id) {
                annual_response_costs[index] = assignedARC;
            }
        });
        RORIObject.annual_response_costs = annual_response_costs;
        localStorage.setItem("RORIString", JSON.stringify(RORIObject));
        goBack();
    }
    else {
        let newARC;
        if (totalChecked) {
            newARC = {
                id: getNewARCId(),
                COI: "",
                COM: "",
                ODC: "",
                IC: "",
                total: totalValue,
            };
        }
        else if (coi != 0 || com != 0 || odc != 0 || ic != 0) {
            newARC = {
                id: getNewARCId(),
                COI: coi,
                COM: com,
                ODC: odc,
                IC: ic,
                total: "",
            };
        }
        annual_response_costs.push(newARC);
        selectedCountermeasure.id_arc = newARC.id;
        countermeasures.forEach((cm, index) => {
            if (cm.id == selectedCountermeasure.id) {
                countermeasures[index] = selectedCountermeasure;
            }
        });
        RORIObject.annual_response_costs = annual_response_costs;
        RORIObject.countermeasures = countermeasures;
        localStorage.setItem("RORIString", JSON.stringify(RORIObject));
        goBack();
    }
}

function removeARC() {
    if (assignedARC) {
        annual_response_costs.forEach(arc => {
            if (arc.id == assignedARC.id) {
                let index = annual_response_costs.indexOf(arc);
                annual_response_costs.splice(index, 1);
            }
        });
        RORIObject.annual_response_costs = annual_response_costs;
        selectedCountermeasure.id_arc = "";
        countermeasures.forEach(cm => {
            if (cm.id == selectedCountermeasure.id) {
                let index = countermeasures.indexOf(cm);
                countermeasures[index] = selectedCountermeasure;
            }
        });
        RORIObject.countermeasures = countermeasures;
        localStorage.setItem("RORIString", JSON.stringify(RORIObject));
        goBack()
    }
    else {
        alert("No annual respnose cost value is assigned to the selected mitigation action.");
    }
}

function toggleTotal() {
    let totalChecked = document.getElementById("giveTotal").checked;
    document.getElementById("coi").disabled = totalChecked;
    document.getElementById("com").disabled = totalChecked;
    document.getElementById("odc").disabled = totalChecked;
    document.getElementById("ic").disabled = totalChecked;
    document.getElementById("totalValue").disabled = !totalChecked;
}

function changeTotal() {
    let totalValue = document.getElementById("totalValue");
    let coi = document.getElementById("coi").valueAsNumber ? document.getElementById("coi").valueAsNumber : 0;
    let com = document.getElementById("com").valueAsNumber ? document.getElementById("com").valueAsNumber : 0;
    let odc = document.getElementById("odc").valueAsNumber ? document.getElementById("odc").valueAsNumber : 0;
    let ic = document.getElementById("ic").valueAsNumber ? document.getElementById("ic").valueAsNumber : 0;
    totalValue.value = Math.a(coi, Math.a(com, Math.a(odc, ic)));
}

function getNewARCId() {
    let id = 1;
    annual_response_costs.forEach(arc => {
        if (arc.id >= id) {
            id = arc.id + 1;
        }
    });
    return id;
}