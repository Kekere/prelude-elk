var RORIObject;

document.addEventListener("DOMContentLoaded", function () {
    if (localStorage.getItem("RORIString")) {
        RORIObject = JSON.parse(localStorage.getItem("RORIString"));
        extract();
    }
    let organizationsList = document.getElementById("organizationsList");
    organizations.forEach(org => {
        let organizationOption = new Option(org.name, org.id);
        organizationsList.add(organizationOption);
    });
    organizationsList.selectedIndex = -1; //no option selected
});

/**
 * After selecting an Organization from the dropdown list, the table of Detrimental Events is filled accordingly.
 * @param {*} selectedOrg - The selected Organization
 */
function getDetrimentalEvents(selectedOrg) {
    let organizationId = selectedOrg.value;
    let detrimentalEventsTable = document.getElementById("detrimentalEventsTable");
    clearTable(detrimentalEventsTable);
    clearTable(document.getElementById("mitigationActionsTable"));
    document.getElementById("roriButton").disabled = true;
    incidents.forEach(incident => {
        if (incident.id_organization == organizationId) {
            let row = detrimentalEventsTable.insertRow();
            row.setAttribute("class", "unhighlighted");
            row.setAttribute("onclick", "selectDetrimentalEvent(this)");
            row.setAttribute("data-value", incident.id);
            let name = row.insertCell(0);
            name.innerHTML = incident.name;
        }
    });
}

var selectedIncidentId = 0; // to save incident id
var selectedIncident = {}; // to save the incident
var organization = {}; // to save the selected organization
var incidentAle = {}; // to save the ALE of the incident
var selectedCountermeasureId = 0;

/**
 * Highlights the detrimental events table's selected row and fills the mitigation actions table accordingly.
 * @param {*} row - Detrimental Event row
 */
function selectDetrimentalEvent(row) { //in case of unselect, clear mitigation actions table
    let detrimentalEventsRows = document.getElementById("detrimentalEventsTable").rows;
    let button = document.getElementById("roriButton");
    for (let de of detrimentalEventsRows) {
        if (de != row) {
            de.className = "unhighlighted";
            selectedIncidentId = 0;
        }
    }
    row.className = row.className == "unhighlighted" ? "highlighted" : "unhighlighted"; //toggle row highlight in case it was selected
    if (row.className == "unhighlighted") {
        selectedIncidentId = 0;
    }
    else {
        selectedIncidentId = row.getAttribute("data-value");
    }
    let mitigationActionsTable = document.getElementById("mitigationActionsTable");
    if (row.className == "unhighlighted") { //to clear mitigation actions table after unselecting a row
        selectedCountermeasureId = 0;
        clearTable(mitigationActionsTable);
    }
    else {
        incidents.forEach(incident => {
            if (String(incident.id) == row.getAttribute("data-value")) {
                clearTable(mitigationActionsTable); //to replace the table's contents
                let mitigationActions = [];
                let mitigationActionsIds = [];
                if (String(typeof incident.id_countermeasure) == "number") {
                    mitigationActionsIds.push(incident.id_countermeasure);
                }
                else if (incident.id_countermeasure.length != 0) {
                    mitigationActionsIds = incident.id_countermeasure.split(",").map(Number);
                }
                countermeasures.forEach(countermeasure => {
                    if (mitigationActionsIds.includes(countermeasure.id)) {
                        mitigationActions.push(countermeasure);
                    }
                });
                mitigationActions.forEach(mitigationAction => {
                    let crow = mitigationActionsTable.insertRow();
                    crow.setAttribute("onclick", "selectMitigationAction(this)");
                    crow.setAttribute("class", "unhighlighted");
                    crow.setAttribute("data-value", mitigationAction.id);
                    let name = crow.insertCell(0);
                    name.innerHTML = mitigationAction.name;
                });
            }
        });
    }
    button.disabled = (Number(selectedIncidentId) == 0);
}

/**
 * Highlights the mitigation action table's selected row.
 * @param {*} row - Mitigation Action row
 */
function selectMitigationAction(row) {
    let mitigationActionsRows = document.getElementById("mitigationActionsTable").rows;
    for (let ma of mitigationActionsRows) {
        if (ma != row) {
            ma.className = "unhighlighted";
        }
    }
    row.className = (row.className == "unhighlighted") ? "highlighted" : "unhighlighted"; //toggle row highlight in case it was selected
}

/**
 * This function is a wrapper for both individual and combined RORI calculations.
 * It is executed when the "Perform RORI Calculation" button is clicked.
 */
function performRoriCalculation() {
    let roriList = performIndividualRori();
    let roriListToCombine = [];
    let avgRori = 0;
    roriList.forEach(element => {
        avgRori = Math.a(avgRori, Math.d(element.rori, roriList.length));
    });
    roriList.forEach(element => {
        if (element.rori >= avgRori && element.countermeasure.totally_restrictive == "no") {
            roriListToCombine.push(element);
        }
    });
    let combinationError = document.getElementById("combinationError");
    let combinedRoriTable = document.getElementById("combinedRoriTable");
    for (let item of roriListToCombine) {
        let rmId = item.countermeasure.id_rm;
        for (let rm of risk_mitigations) {
            if (rm.id == rmId) {
                if (!rm.EF && !rm.COV) {
                    combinationError.removeAttribute("class");
                    combinationError.innerHTML = "Missing Effectiveness and/or Coverage factor(s). Cannot perfom combined RORI evalutation.";
                    clearTable(combinedRoriTable);
                    window.scrollTo({ top: document.getElementById("roriDiv").offsetTop, behavior: "smooth" });
                    return;
                }
            }
        }
    }
    combinationError.setAttribute("class", "hidden");
    performCombinedRori(roriListToCombine);
    window.scrollTo({ top: document.getElementById("roriDiv").offsetTop, behavior: "smooth" });
}

/**
 * Calculates the RORI index for each countermeasure, fills the individual RORI table accordingly, 
 * and returns an array in which each element is an object containing a countermeasure, its RORI index and its assigned equipment.
 * @returns {Array} roriList
 */
function performIndividualRori() {
    selectedIncident = {};
    let organizationId = 0;
    let aiv = 0, countermeasureRm = 0, countermeasureArc = 0, rori = 0, incidentTotalAle = 0;
    let roriList = [];
    incidents.forEach(incident => {
        if (incident.id == selectedIncidentId) {
            selectedIncident = incident;
            organizationId = Number(incident.id_organization);
        }
    });
    annual_loss_expectancies.forEach(ale => { //get the ALE of the incident
        if (ale.id == selectedIncident.id_ale) {
            incidentTotalAle = ale.total;
            incidentAle = ale;
        }
    });
    // get the countermeasures assigned to the incident
    let incidentCountermeasures = [];
    let countermeasureIds = [];
    if (String(typeof selectedIncident.id_countermeasure) == "number") {
        countermeasureIds.push(selectedIncident.id_countermeasure);
    }
    else if (selectedIncident.id_countermeasure.length != 0) {
        countermeasureIds = selectedIncident.id_countermeasure.split(",").map(Number);
    }
    countermeasures.forEach(countermeasure => {
        if (countermeasureIds.includes(countermeasure.id)) {
            incidentCountermeasures.push(countermeasure);
        }
    });
    organizations.forEach(org => {
        if (org.id == organizationId) {
            organization = org;
        }
    });
    aiv = getOrganizationAIV(organization);
    //get the rm of each countermeasure assigned to the incident
    incidentCountermeasures.forEach(countermeasure => {
        countermeasureRm = 0;
        countermeasureArc = 0;
        risk_mitigations.forEach(rm => {
            if (rm.id == countermeasure.id_rm) {
                if ((rm.EF && rm.EF != "") && (rm.COV && rm.COV != "")) {
                    countermeasureRm = Math.m(rm.EF, rm.COV);
                }
                else if (rm.RM && rm.RM != "") {
                    countermeasureRm = Math.m(rm.RM, 1);
                }
            }
        });
        annual_response_costs.forEach(arc => {
            if (arc.id == countermeasure.id_arc) {
                countermeasureArc = arc.total ? arc.total : arc.COI + arc.COM + arc.ODC + arc.IC;
            }
        });
        rori = Math.m(Math.d(Math.m(incidentTotalAle, countermeasureRm), Math.a(countermeasureArc, aiv)), 100);
        let countermeasureEquipmentIds = [];

        if (String(typeof countermeasure.id_equipment) == "number") {
            countermeasureEquipmentIds.push(countermeasure.id_equipment);
        }
        else if (countermeasure.id_equipment.length != 0) {
            countermeasureEquipmentIds = countermeasure.id_equipment.split(",").map(Number);
        }

        let countermeasureEquipment = [];
        equipment.forEach(eq => {
            if (countermeasureEquipmentIds.includes(eq.id)) {
                countermeasureEquipment.push(eq);
            }
        });
        let aux = {
            countermeasure: countermeasure,
            rori: rori,
            equipment: countermeasureEquipment,
            arc: countermeasureArc,
        };
        roriList.push(aux);
    });

    let individualRoriHeader = document.getElementById("individualRoriHeader");
    individualRoriHeader.innerHTML = "'" + selectedIncident.name + "' Detrimental Event at the organization '" + organization.name + "'";
    let roriDiv = document.getElementById("roriDiv");
    roriDiv.setAttribute("class", "");
    let individualRoriTable = document.getElementById("individualRoriTable");
    clearTable(individualRoriTable); // in case an evaluation occured before
    roriList.forEach(aux => {
        if (aux.rori != 0) {
            let row = individualRoriTable.insertRow();
            let id = row.insertCell(0);
            id.innerHTML = aux.countermeasure.id;
            let name = row.insertCell(1);
            name.innerHTML = aux.countermeasure.name;
            let pep = row.insertCell(2);
            if (aux.equipment) {
                pep.innerHTML = aux.equipment.map(eq => eq.name).join(", ");
            }
            let roriCell = row.insertCell(3);
            roriCell.innerHTML = aux.rori.toFixed(2);
            if (aux.rori == Math.max.apply(Math, roriList.map(function (o) { return o.rori }))) { // to get the max rori index, and highlight the corresponding row
                row.className = "gold";
                row.setAttribute("class-value", "gold"); // highlights in gold the best countermeasure
            }
        }
    });
    return roriList;
}

/**
 * Generates all valid Countermeasures combinations, and computes each one's RORI index.
 * Fills the Combined RORI table accordingly, and highlights the row with the highest RORI value in gold.
 * @param {Array} roriList - Array of Countermeasures and their correspoding RORI index.
 * @returns {Array} roriCombinedList.
 */
function performCombinedRori(roriList) {
    let roriCombinedList = [];
    let mutRestrictive = [];
    for (let L = 0; L < roriList.length + 1; L++) {
        combinations(roriList, L).forEach(subset => {
            if (subset.length > 1) {
                let aux = subset;
                subset.forEach(element => {
                    aux.forEach(auxElement => {
                        if (element.countermeasure != auxElement.countermeasure) {
                            let restrictionIds = [];
                            if (String(typeof auxElement.countermeasure.restriction) == "number") {
                                restrictionIds.push(auxElement.countermeasure.restriction);
                            }
                            else if (auxElement.countermeasure.restriction.length != 0) {
                                restrictionIds = auxElement.countermeasure.restriction.split(",").map(Number);
                            }
                            if (restrictionIds.includes(element.countermeasure.id)) {
                                if (!arrayInArray(mutRestrictive, [element.countermeasure, auxElement.countermeasure])) { //to prevent duplicates
                                    mutRestrictive.push([element.countermeasure, auxElement.countermeasure]);
                                }
                            }
                        }
                    });
                });
            }
        });
    }

    for (let L = 0; L < roriList.length + 1; L++) {
        combinations(roriList, L).forEach(subset => {
            if (subset.length > 1) {
                let idCountermeasures = [];
                subset.forEach(element => {
                    idCountermeasures.push(element.countermeasure);
                });
                let flag = false;
                mutRestrictive.forEach(restriction => {
                    let intersectionSet = intersection(idCountermeasures, restriction);
                    if (JSON.stringify(intersectionSet) === JSON.stringify(restriction)) {
                        flag = true;
                    }
                });
                if (!flag) {
                    let arcSubset = 0, rmIndiv = 0;
                    subset.forEach(element => {
                        arcSubset += element.arc;
                        risk_mitigations.forEach(rm => {
                            if (element.countermeasure.id_rm == rm.id) {
                                rmIndiv = Math.a(rmIndiv, Math.m(rm.COV, rm.EF));
                            }
                        });
                    });
                    let rmIntersection = 0;
                    let covInt = 0;
                    let efList = [], covList = [];
                    for (let l = 0; l < subset.length + 1; l++) {
                        let rmSubSubset = 0;
                        combinations(subset, l).forEach(subSubset => {
                            if (subSubset.length > 1) {
                                efList = [];
                                covList = [];
                                subSubset.forEach(element => {
                                    risk_mitigations.forEach(rm => {
                                        if (element.countermeasure.id_rm == rm.id) {
                                            covList.push(Math.m(rm.COV, 1));
                                            efList.push(rm.EF);
                                        }
                                    });
                                });
                                let covIntLow;
                                covInt = 0;
                                if (sum(covList) <= (subSubset.length - 1)) {
                                    covIntLow = 0;
                                }
                                else {
                                    covIntLow = Math.s(sum(covList), Math.s(subSubset.length, 1));
                                }
                                covInt = Math.d(Math.a(covIntLow, Math.min(...covList)), 2);
                                let rmInt = Math.m(covInt, Math.min(...efList));
                                rmSubSubset = Math.a(rmSubSubset, rmInt);
                            }
                        });
                        rmIntersection += Math.m(Math.pow(-1, l), rmSubSubset);
                    }
                    let rmCombined = Math.s(rmIndiv, rmIntersection);
                    let roriComb = Math.m(Math.d(Math.s(Math.m(incidentAle.total, rmCombined), arcSubset), Math.a(arcSubset, getOrganizationAIV(organization))), 100);
                    let auxDict = {
                        countermeasures: idCountermeasures,
                        ARC: arcSubset,
                        COV: covInt,
                        EF: Math.min(...efList),
                        RM: rmCombined,
                        rori: roriComb,
                    }
                    roriCombinedList.push(auxDict);
                }
            }
        });
    }
    let combinedRoriTable = document.getElementById("combinedRoriTable");
    clearTable(combinedRoriTable); // in case an evaluation occured before
    roriCombinedList.forEach(element => {
        let row = combinedRoriTable.insertRow();
        let combos = row.insertCell(0);
        combos.innerHTML = element.countermeasures.map(a => a.id).join(", ");
        let arc = row.insertCell(1);
        arc.innerHTML = element.ARC.toFixed(1);
        let cov = row.insertCell(2);
        cov.innerHTML = element.COV.toFixed(2);
        let ef = row.insertCell(3);
        ef.innerHTML = element.EF.toFixed(1);
        let rm = row.insertCell(4);
        rm.innerHTML = element.RM.toFixed(2);
        let roriCell = row.insertCell(5);
        roriCell.innerHTML = element.rori.toFixed(2);
        if (element.rori == Math.max.apply(Math, roriCombinedList.map(function (o) { return o.rori }))) { // to get the max rori index, and highlight the corresponding row(s)
            row.className = "gold";
            row.setAttribute("class-value", "gold"); // highlights in gold the best countermeasure
        }
    });
    return roriCombinedList;
}

/**
 * Generates all possible combination from a given Array
 * @param {Array} arr - Array to generate combinations from
 * @returns {Array}
 */
function getCombinations(arr) {
    let combos = [];
    let temp = [];
    let slent = Math.pow(2, arr.length);
    for (let i = 0; i < slent; i++) {
        temp = [];
        for (let j = 0; j < arr.length; j++) {
            if ((i & Math.pow(2, j))) {
                temp.push(arr[j]);
            }
        }
        if (temp.length > 0) {
            combos.push(temp);
        }
    }
    combos.sort((a, b) => a.length - b.length);
    return combos;
}

/**
 * Checks if an input array contains an array as element.
 * @param {Array} array - Input array.
 * @param {Array} item - Array to check.
 * @returns {boolean} Returns true if the input array contains the array as element.
 */
function arrayInArray(array, item) {
    let item_as_string = JSON.stringify(item);
    return array.some(function (element) {
        return JSON.stringify(element) === item_as_string;
    });
}

/**
 * Takes two arrays containing countermeasures as input and returns their intersection.
 * @param {Array} arr1 - First array.
 * @param {Array} arr2 - Second array.
 * @returns {Array} The intersection of the two arrays.
 */
function intersection(arr1, arr2) {
    return arr1.filter(item1 => arr2.some(item2 => item1.id === item2.id));
}

/**
 * Takes an array as input and returns the sum of its elements if not empty, else 0.
 * @param {Array} arr - Input array.
 * @returns {number} Sum of the elements.
 */
function sum(arr) {
    return arr.reduce(function (a, b) { return Math.a(a, b); }, 0);
}

/**
 * Calculates the organization's AIV.
 * @param {*} org 
 * @returns {number} AIV.
 */
function getOrganizationAIV(org) {
    let aiv = 0;
    org.AEV.forEach(aev => {
        aiv += aev.AEV;
    });
    return aiv;
}

/**
 * Generates all combinations of an array based on a given length.
 * @param {Array} array - Array of input elements.
 * @param {number} comboLength - desired length of combinations.
 * @returns {Array} Array of combination arrays
 */
function combinations(array, comboLength) {
    let sourceLength = array.length;
    if (comboLength > sourceLength) return [];
    let combos = []; //stores valid combinations
    let makeNextCombos = (workingCombo, currentIndex, remainingCount) => {
        let oneAwayFromComboLength = remainingCount == 1;
        for (let sourceIndex = currentIndex; sourceIndex < sourceLength; sourceIndex++) {
            let next = [...workingCombo, array[sourceIndex]];
            if (oneAwayFromComboLength) {
                combos.push(next);
            }
            else {
                makeNextCombos(next, sourceIndex + 1, remainingCount - 1);
            }
        }
    };
    makeNextCombos([], 0, comboLength);
    return combos;
}
