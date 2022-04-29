var selectedCountermeasure, restrictions, RORIObject;

document.addEventListener("DOMContentLoaded", function () {
    if (localStorage.getItem("RORIString")) {
        RORIObject = JSON.parse(localStorage.getItem("RORIString"));
        extract();
    }
    if (sessionStorage.getItem("selectedCountermeasure")) {
        selectedCountermeasure = JSON.parse(sessionStorage.getItem("selectedCountermeasure"));
        restrictions = getRestrictions(selectedCountermeasure);
        let availableCountermeasures = document.getElementById("availableCountermeasures");
        let restrictionsTable = document.getElementById("restrictions");
        countermeasures.forEach(countermeasure => {
            if (countermeasure.id != selectedCountermeasure.id) {
                let row;
                if (restrictions.includes(countermeasure)) {
                    row = restrictionsTable.insertRow();
                    row.setAttribute("onclick", "selectRestriction(this)");
                }
                else {
                    row = availableCountermeasures.insertRow();
                    row.setAttribute("onclick", "selectCountermeasure(this)");
                }
                row.setAttribute("class", "unhighlighted");
                row.setAttribute("data-value", countermeasure.id);
                let name = row.insertCell(0);
                name.innerHTML = countermeasure.name;
                let description = row.insertCell(1);
                description.innerHTML = countermeasure.description;
            }
        });
    }
    else {
        if (confirm("No Mitigation Action was selected.")) {
            window.history.back(); //in case there was a problem
        }
    }
});

function getRestrictions(countermeasure) {
    let restrictionsIds = [];
    let restrict = [];
    if (String(typeof countermeasure.restriction) == "number") {
        restrictionsIds.push(countermeasure.restriction);
    }
    else if (countermeasure.restriction.length != 0) {
        restrictionsIds = countermeasure.restriction.split(",").map(Number);
    }
    else {
        return [];
    }
    countermeasures.forEach(cm => {
        if (restrictionsIds.includes(cm.id)) {
            restrict.push(cm);
        }
    });
    return restrict;
}

var availableCountermeasureSelected = false, availableCountermeasureId = 0;

function selectCountermeasure(row) {
    let restrictionsRows = document.getElementById("restrictions").rows;
    for (let cm of restrictionsRows) {
        cm.className = "unhighlighted";
    }
    restrictionSelected = false;
    restrictionId = 0;
    let availableCountermeasrues = document.getElementById("availableCountermeasures").rows;
    for (let cm of availableCountermeasrues) {
        if (cm != row) {
            cm.className = "unhighlighted";
        }
    }
    row.className = row.className == "unhighlighted" ? "highlighted" : "unhighlighted";
    availableCountermeasureSelected = row.className == "highlighted";
    availableCountermeasureId = Number.parseInt(row.getAttribute("data-value"));
}

var restrictionSelected = false, restrictionId = 0;

function selectRestriction(row) {
    let availableCountermeasures = document.getElementById("availableCountermeasures").rows;
    for (let cm of availableCountermeasures) {
        cm.className = "unhighlighted";
    }
    availableCountermeasureSelected = false;
    availableCountermeasureId = 0;
    let restrictionsRows = document.getElementById("restrictions").rows;
    for (let cm of restrictionsRows) {
        if (cm != row) {
            cm.className = "unhighlighted";
        }
    }
    row.className = row.className == "unhighlighted" ? "highlighted" : "unhighlighted";
    restrictionSelected = row.className == "highlighted";
    restrictionId = Number.parseInt(row.getAttribute("data-value"));
}

function assignRestriction() {
    if (!availableCountermeasureSelected) {
        alert("Please select a mitigation action.");
    }
    else {
        countermeasures.forEach((cm, index) => {
            if (cm.id == selectedCountermeasure.id) {
                let temp = restrictions.map(x => x.id);
                temp.push(availableCountermeasureId);
                selectedCountermeasure.restriction = temp.join(", ");
                countermeasures[index] = selectedCountermeasure;
                RORIObject.countermeasures = countermeasures;
                sessionStorage.setItem("selectedCountermeasure", JSON.stringify(selectedCountermeasure));
                localStorage.setItem("RORIString", JSON.stringify(RORIObject));
                window.location.reload();
            }
        });
    }
}

function removeRestriction() {
    if (!restrictionSelected) {
        alert("Please select a restriction.");
    }
    else {
        countermeasures.forEach((cm, index) => {
            if (cm.id == selectedCountermeasure.id) {
                selectedCountermeasure.restriction = restrictions.map(x => x.id).filter(x => x != restrictionId).join(", ");
                countermeasures[index] = selectedCountermeasure;
                RORIObject.countermeasures = countermeasures;
                sessionStorage.setItem("selectedCountermeasure", JSON.stringify(selectedCountermeasure));
                localStorage.setItem("RORIString", JSON.stringify(RORIObject));
                window.location.reload();
            }
        });
    }
}