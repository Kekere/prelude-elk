var selectedCountermeasure, assignedRM, RORIObject;

document.addEventListener("DOMContentLoaded", function () {
    if (localStorage.getItem("RORIString")) {
        RORIObject = JSON.parse(localStorage.getItem("RORIString"));
        extract();
    }
    if (sessionStorage.getItem("selectedCountermeasure")) {
        selectedCountermeasure = JSON.parse(sessionStorage.getItem("selectedCountermeasure"));
        if (sessionStorage.getItem("assignedRM")) {
            assignedRM = JSON.parse(sessionStorage.getItem("assignedRM"));
            if (assignedRM) {
                if (assignedRM.RM) {
                    document.getElementById("totalValue").value = String(Math.m(assignedRM.RM, 100))
                }
                else {
                    document.getElementById("ef").value = Math.m(assignedRM.EF, 100);
                    document.getElementById("cov").value = Math.m(assignedRM.COV, 100);
                    document.getElementById("totalValue").value = Math.m(Math.m(assignedRM.EF, assignedRM.COV), 100);
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

function assignRM() {
    let ef = document.getElementById("ef").valueAsNumber ? document.getElementById("ef").valueAsNumber : 0;
    let cov = document.getElementById("cov").valueAsNumber ? document.getElementById("cov").valueAsNumber : 0;
    let totalValue = document.getElementById("totalValue").valueAsNumber;
    let totalChecked = document.getElementById("giveTotal").checked;
    if (totalValue <= 0) {
        alert("Total value should be greater than 0.");
        return;
    }
    if (assignedRM) {
        if (totalChecked) {
            assignedRM.EF = "";
            assignedRM.COV = "";
            assignedRM.RM = Math.d(totalValue, 100);
        }
        else if (ef != 0 && cov != 0) {
            assignedRM.EF = Math.d(ef, 100);
            assignedRM.COV = Math.d(cov, 100);
            assignedRM.RM = "";
        }
        risk_mitigations.forEach((rm, index) => {
            if (rm.id == assignedRM.id) {
                risk_mitigations[index] = assignedRM;
            }
        });
        RORIObject.risk_mitigations = risk_mitigations;
        localStorage.setItem("RORIString", JSON.stringify(RORIObject));
        goBack();
    }
    else {
        let newRM;
        if (totalChecked) {
            newRM = {
                id: getNewRMId(),
                EF: "",
                COV: "",
                RM: Math.d(totalValue, 100),
            };
        }
        else {
            newRM = {
                id: getNewRMId(),
                EF: Math.d(ef, 100),
                COV: Math.d(cov, 100),
                RM: "",
            }
        }
        risk_mitigations.push(newRM);
        selectedCountermeasure.id_rm = newRM.id;
        sessionStorage.setItem("selectedCountermeasure", selectedCountermeasure);
        countermeasures.forEach((cm, index) => {
            if (cm.id == selectedCountermeasure.id) {
                countermeasures[index] = selectedCountermeasure;
            }
        });
        RORIObject.risk_mitigations = risk_mitigations;
        RORIObject.countermeasures = countermeasures;
        localStorage.setItem("RORIString", JSON.stringify(RORIObject));
        goBack();
    }
}

function removeRM() {
    if (assignedRM) {
        risk_mitigations.forEach(rm => {
            if (rm.id == assignedRM.id) {
                let index = risk_mitigations.indexOf(rm);
                risk_mitigations.splice(index, 1);
            }
        });
        RORIObject.risk_mitigations = risk_mitigations;
        selectedCountermeasure.id_rm = "";
        countermeasures.forEach(cm => {
            if (cm.id == selectedCountermeasure.id) {
                let index = countermeasures.indexOf(cm);
                countermeasures[index] = selectedCountermeasure;
            }
        });
        RORIObject.countermeasures = countermeasures;
        localStorage.setItem("RORIString", JSON.stringify(RORIObject));
        goBack();
    }
    else {
        alert("No risk mitigation value is assigned to the selected mitigation action.");
    }
}

function toggleTotal() {
    let totalChecked = document.getElementById("giveTotal").checked;
    document.getElementById("ef").disabled = totalChecked;
    document.getElementById("cov").disabled = totalChecked;
    document.getElementById("totalValue").disabled = !totalChecked;
}

function changeTotal() {
    let totalValue = document.getElementById("totalValue");
    let ef = document.getElementById("ef").valueAsNumber ? document.getElementById("ef").valueAsNumber : 0;
    let cov = document.getElementById("cov").valueAsNumber ? document.getElementById("cov").valueAsNumber : 0;
    totalValue.value = Math.d(Math.m(ef, cov), 100);
}

function getNewRMId() {
    let id = 1;
    risk_mitigations.forEach(rm => {
        if (rm.id >= id) {
            id = rm.id + 1;
        }
    });
    return id;
}