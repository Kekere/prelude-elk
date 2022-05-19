var RORIObject;

document.addEventListener("DOMContentLoaded", function () {
    if (localStorage.getItem("RORIString")) {
        RORIObject = JSON.parse(localStorage.getItem("RORIString"));
        extract();
    }
    let organizationsList = document.getElementById("organizationsList");
    organizations.forEach(organization => {
        let organizationOption = new Option(organization.name, organization.id);
        organizationsList.add(organizationOption);
    });
    organizationsList.selectedIndex = -1; //no option selected
});

function getDetrimentalEvents(selectedValue) {
    let organizationId = selectedValue.value;
    let detrimentalEventsTable = document.getElementById("detrimentalEventsTable");
    clearTable(detrimentalEventsTable);
    clearTable(document.getElementById("mitigationActionsTable"));
    document.getElementById("graphButton").disabled = true;
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

var detrimentalEventSelected = false, mitigationActionSelected = false; //booleans used to toggle the graphical representation button
var selectedIncidentId = 0; // to save incident id
var selectedIncident = {}; // to save the incident

/**
 * Highlights the detrimental events table's selected row and fills the mitigation actions table accordingly.
 * @param {*} row - Detrimental Event row
 */
function selectDetrimentalEvent(row) { //in case of unselect, clear mitigation actions table
    let detrimentalEventsRows = document.getElementById("detrimentalEventsTable").rows;
    let button = document.getElementById("graphButton");
    for (let de of detrimentalEventsRows) {
        if (de != row) {
            de.className = "unhighlighted";
            selectedIncident = 0;
        }
    }
    row.className = row.className == "unhighlighted" ? "highlighted" : "unhighlighted"; //toggle row highlight in case it was selected
    let mitigationActionsTable = document.getElementById("mitigationActionsTable");
    if (row.className == "unhighlighted") { //to clear mitigation actions table after unselecting a row
        clearTable(mitigationActionsTable);
        selectedIncidentId = 0;
    }
    else {
        incidents.forEach(incident => {
            if (String(incident.id) == row.getAttribute("data-value")) {
                selectedIncidentId = incident.id;
                clearTable(mitigationActionsTable); //to replace the table's contents
                let mitigationActionsIds = [];
                let mitigationActions = [];
                if (String(typeof incident.id_countermeasure) == "number") {
                    mitigationActionsIds.push(incident.id_countermeasure);
                }
                else if (incident.id_countermeasure.length != 0) {
                    mitigationActionsIds = incident.id_countermeasure.split(",").map(Number);
                }
                else {
                    return;
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
                    let id = crow.insertCell(0);
                    id.innerHTML = mitigationAction.id;
                    let name = crow.insertCell(1);
                    name.innerHTML = mitigationAction.name;
                });
            }
        });
    }
    detrimentalEventSelected = row.className == "highlighted";
    mitigationActionSelected = false; //
    button.disabled = !(detrimentalEventSelected && mitigationActionSelected);
}

/**
 * Highlights the mitigation action table's selected row and enables the RORI evaluation button.
 * @param {*} row - Mitigation Action row
 */
function selectMitigationAction(row) {
    let button = document.getElementById("graphButton");
    let mitigationActionsRows = document.getElementById("mitigationActionsTable").rows;
    row.className = (row.className == "unhighlighted") ? "highlighted" : "unhighlighted"; //toggle row highlight in case it was selected
    mitigationActionSelected = false;
    for (let ma of mitigationActionsRows) {
        if (ma.className == "highlighted") {
            mitigationActionSelected = true;
        }
    }
    button.disabled = !(detrimentalEventSelected && mitigationActionSelected && document.getElementById("excelFile").files[0]);
}

var colors = [];

/**
 * This function finds the selected attack and countermeasures, checks if they exist in the input excel file,
 * if not, it alerts the user, otherwise, it displays the attack and countermeasures volumes.
 */
function plot() {
    colors = ["black", "royalblue", "rosybrown", "powderblue", "indianred", "maroon", "palegreen", "cyan",
        "deepskyblue", "limegreen", "blueviolet", "olive", "gray", "darkorange", "magenta", "yellow", "blue", "green"];
    // read from excel file and store data into a json object
    // data is already prepared when the excel file is loaded
    // filter attacks, and countermeasures according to the selected attack and countermeasure(s)
    document.getElementById("graph").setAttribute("class", "");
    let incidentName = ""; // make an array of incidentsNames
    let mitigationActionsNames = [];
    incidents.forEach(incident => {
        if (incident.id == selectedIncidentId) {
            incidentName = incident.name;
        }
    });
    let mitigationActionsTable = document.getElementById("mitigationActionsTable");
    let rows = mitigationActionsTable.rows;
    for (let row of rows) {
        if (row.className == "highlighted") {
            countermeasures.forEach(cm => {
                if (String(cm.id) == row.cells[0].innerHTML) {
                    mitigationActionsNames.push(cm.name.replace("-", " ").split(" "));
                }
            });
        }
    }
    let attacksNames = [], selectedAttack = []; // although one attack can be selected, however, having the same format of countermeasures would make it optimal
    let selectedAttackExists = false;
    attackSpecs.map(attack => attacksNames.push(attack.description));
    attacksNames.forEach(attackName => {
        if (incidentName.toLowerCase().includes(attackName.toLowerCase())) {
            selectedAttackExists = true;
        }
    });
    if (!selectedAttackExists) {
        alert("Invalid Detrimental Event.");
        return;
    }
    if (attacksNames.includes(incidentName.toLowerCase()) || selectedAttackExists) {
        attackSpecs.forEach(attack => {
            if (attack.description.toLowerCase().includes(incidentName.toLowerCase()) || incidentName.toLowerCase().includes(attack.description.toLowerCase())) {
                selectedAttack.push(attack);
            }
        });
    }
    else {
        alert("Invalid Detrimental Event.");
        return;
    }

    let countermeasuresNames = [], selectedCountermeasures = [], temp = [];
    countermeasuresSpecs.map(cm => countermeasuresNames.push(cm.description.replace("-", " ")));
    let times = 0;
    countermeasuresNames.forEach(cmName => {
        mitigationActionsNames.forEach(maName => {
            times = 0;
            for (let name of maName) {
                if (cmName.toLowerCase().includes(name.toLowerCase())) {
                    times++;
                }
            }
            if (times >= 2) {
                temp.push(cmName);
            }
        });
    });
    if (temp.length !== mitigationActionsNames.length) { // in case they are different, it means not all selected countermeasures have been found in the excel file, thus alert and return
        alert("Invalid Countermeasure(s)");
        return;
    }
    countermeasuresSpecs.forEach(cm => {
        temp.forEach(name => {
            if (cm.description.replace("-", " ") === name) {
                selectedCountermeasures.push(cm);
            }
        });
    });

    // extract points for attack start
    let selectedAttackCoordinates = [];
    selectedAttack.forEach(attack => {
        if (isSimpleRCUList(attack)) {
            selectedAttackCoordinates = extractPointsFromSimpleRCU(attack, true);
        }
        else {
            selectedAttackCoordinates = extractPointsFromComplexRCU(attack, true);
        }
    });
    // extract points for attack end

    // extract points for countermeasures start
    let selectedCountermeasuresCoordinates = [];
    selectedCountermeasures.forEach(cm => {
        let cmCoordinates = [];
        if (isSimpleRCUList(cm)) {
            cmCoordinates = extractPointsFromSimpleRCU(cm, false);
        }
        else {
            cmCoordinates = extractPointsFromComplexRCU(cm, false);
        }
        selectedCountermeasuresCoordinates = selectedCountermeasuresCoordinates.concat(cmCoordinates);
    });
    // extract points for countermeasures end

    // join the attack and countermeasures arrays
    let allCoordinates = selectedAttackCoordinates.concat(selectedCountermeasuresCoordinates);
    let layout = {
        title: "Attack Volume Representation",
        height: 750,
        legend: {
            yanchor: "top",
            y: 0.99,
            xanchor: "left",
            x: 0.01,
            bgcolor: "rgba(0, 0, 0, 0)"
        },
        scene: {
            camera: {
                eye: {
                    x: 2,
                    y: -1.8,
                    z: 1.5,
                }
            },
            xaxis: {
                title: "Resource",
                range: [0, Math.max.apply(Math, allCoordinates.map(function (row) { return Math.max.apply(Math, row.x) })) + 80],
            },
            yaxis: {
                title: "Channel",
                range: [0, Math.max.apply(Math, allCoordinates.map(function (row) { return Math.max.apply(Math, row.y) })) + 80],
            },
            zaxis: {
                title: "User Account",
                range: [0, Math.max.apply(Math, allCoordinates.map(function (row) { return Math.max.apply(Math, row.z) })) + 100],
            },
        }
    };
    let config = { responsive: true };
    Plotly.newPlot('graph', allCoordinates, layout, config);
    // after plotting, the window automatically scrolls to the graph div
    document.getElementById("graph").scrollIntoView({ behavior: "smooth" });
}

/**
 * This function allows to know if a given list of RCU belonging to an attack or a countermeasure is simple.
 * @param {*} item - Attack or Countermeasure.
 * @returns {Boolean} isSimpleRCUList
 */
function isSimpleRCUList(item) {
    let l0 = item.resource.elements.length * item.resource.elements[0].length;
    let l1 = item.channel.elements.length * item.channel.elements[0].length;
    let l2 = item.user.elements.length * item.user.elements[0].length;
    if (l0 == 2 && l1 == 2 && l2 == 2) {
        return true;
    }
    return false;
}

/**
 * From a simple RCU of an attack or countermeasure, this function extracts needed points to represent the volume.
 * @param {*} item - Attack or Countermeasure.
 * @param {boolean} isAttack - Used too adjust certain values.
 * @returns {Array} result.
 */
function extractPointsFromSimpleRCU(item, isAttack) {
    let result = [];
    let x = [item.resource.start[0], item.resource.end[0], item.resource.end[0], item.resource.start[0], item.resource.start[0], item.resource.end[0], item.resource.end[0], item.resource.start[0]];
    let y = [item.channel.start[0], item.channel.start[0], item.channel.end[0], item.channel.end[0], item.channel.start[0], item.channel.start[0], item.channel.end[0], item.channel.end[0]];
    let z = [item.user.start[0], item.user.start[0], item.user.start[0], item.user.start[0], item.user.end[0], item.user.end[0], item.user.end[0], item.user.end[0]];
    let pc = {
        type: "mesh3d",
        x: x,
        y: y,
        z: z,
        opacity: 0.4,
        color: isAttack ? "red" : colors.pop(), // color red is associated with the attack
        i: [7, 0, 0, 0, 4, 4, 6, 6, 4, 0, 3, 2],
        j: [3, 4, 1, 2, 5, 6, 5, 2, 0, 1, 6, 3],
        k: [0, 7, 2, 3, 6, 7, 1, 1, 5, 5, 7, 6],
        name: item.description + " " + item.code,
        legendgroup: item.description + " " + item.code, // only one volume of an element, meaning only one legend
        showlegend: true,
    };
    result.push(pc);
    return result;
}

/**
 * From a complex RCU of an attack or countermeasure, this function gets all permutations of that RCU to form simple RCUs,
 * extracts all needed points from each combination to represent multiple volumes of the given attack or countermeasure.
 * @param {*} item - Attack or Countermeasure.
 * @param {boolean} isAttack - Used to adjust certain values.
 * @returns {Array} result.
 */
function extractPointsFromComplexRCU(item, isAttack) { // add countermeasureOrAttack argument to change the opacity and color accordingly
    // "start" and "end" are arrays containing the starting and ending points of resource, channel and user respectively
    let start = listAfterPermutation(item.resource.start, item.channel.start, item.user.start);
    let end = listAfterPermutation(item.resource.end, item.channel.end, item.user.end);
    if (start.length != end.length) {
        alert("Invalid Coordinates");
        return [];
    }
    let result = [];
    let color = colors.pop();
    for (let i = 0; i < start.length; i++) {
        let x = [], y = [], z = [];
        x.push(start[i][0], end[i][0], end[i][0], start[i][0], start[i][0], end[i][0], end[i][0], start[i][0]);
        y.push(start[i][1], start[i][1], end[i][1], end[i][1], start[i][1], start[i][1], end[i][1], end[i][1]);
        z.push(start[i][2], start[i][2], start[i][2], start[i][2], end[i][2], end[i][2], end[i][2], end[i][2]);
        let pc = {
            type: "mesh3d",
            x: x,
            y: y,
            z: z,
            opacity: 0.4,
            color: isAttack ? "red" : color, // color red is associated with the attack
            i: [7, 0, 0, 0, 4, 4, 6, 6, 4, 0, 3, 2],
            j: [3, 4, 1, 2, 5, 6, 5, 2, 0, 1, 6, 3],
            k: [0, 7, 2, 3, 6, 7, 1, 1, 5, 5, 7, 6],
            name: item.description + " " + item.code,
            legendgroup: item.description + " " + item.code,
            showlegend: i == 0, // to show one legend for all the volumes of the same element
        }
        result.push(pc);
    }
    return result;
}

/**
 * This function is used to return an Array containing the length of every dimension (Resouce, Channel, User Account).
 * @param {Array} r - Array containing points on the Resource dimension.
 * @param {Array} c - Array containing points on the Channel dimension.
 * @param {Array} u - Array containing points on the User Account dimension.
 * @returns {Array} sizes.
 */
function extractSizes(r, c, u) {
    return [r.length, c.length, u.length];
}

/**
 * Returns an Array containing all possible permutations of the points of each dimension.
 * @param {Array} r - Array containing points on the Resource dimension.
 * @param {Array} c - Array containing points on the Channel dimension.
 * @param {Array} u - Array containing points on the User Account dimension.
 * @returns {Array} result.
 */
function listAfterPermutation(r, c, u) {
    let sizes = extractSizes(r, c, u);
    let result = [];
    if (sizes[0] == 1) {
        if (sizes[1] == 1) {
            if (sizes[2] == 1) {
                result = [r[0], c[0], u[0]];
            }
            else {
                for (let i = 0; i < sizes[2]; i++) {
                    result.push([r[0], c[0], u[i]]);
                }
            }
        }
        else {
            if (sizes[2] == 1) {
                for (let i = 0; i < sizes[1]; i++) {
                    result.push([r[0], c[i], u[0]]);
                }
            }
            else {
                for (let i = 0; i < sizes[1]; i++) {
                    for (let j = 0; j < sizes[2]; j++) {
                        result.push([r[0], c[i], u[j]]);
                    }
                }
            }
        }
    }
    else {
        if (sizes[1] == 1) {
            if (sizes[2] == 1) {
                for (let i = 0; i < sizes[0]; i++) {
                    result.push([r[i], c[0], u[0]]);
                }
            }
            else {
                for (let i = 0; i < sizes[0]; i++) {
                    for (let j = 0; j < sizes[2]; j++) {
                        result.push([r[i], c[0], u[j]]);
                    }
                }
            }
        }
        else {
            if (sizes[2] == 1) {
                for (let i = 0; i < sizes[0]; i++) {
                    for (let j = 0; j < sizes[1]; j++) {
                        result.push([r[i], c[j], u[0]]);
                    }
                }
            }
            else {
                for (let i = 0; i < sizes[0]; i++) {
                    for (let j = 0; j < sizes[1]; j++) {
                        for (let k = 0; k < sizes[2]; k++) {
                            result.push([r[i], c[j], u[k]]);
                        }
                    }
                }
            }
        }
    }
    return result;
}

var systemSpecs, attackSpecs, countermeasuresSpecs;

/**
 * Stores data found in the input file in corresponding variables.
 * @param {*} input - Input file.
 */
function excelToJson(input) {
    let button = document.getElementById("graphButton");
    if (!input.files[0]) {
        button.disabled = true;
        return;
    }
    let system = [], listOfAttacks = [], listOfCountermeasures = [];
    systemSpecs = {
        userAccounts: [],
        channel: [],
        resource: [],
    };
    attackSpecs = [];
    countermeasuresSpecs = [];
    readXlsxFile(input.files[0]).then(function (rows) { // by default, the first sheet is read
        system = rows;
        system.forEach((row, index) => {
            if (index > 2) {
                if (row[0]) {
                    systemSpecs.userAccounts.push({
                        userId: row[0],
                        userName: row[1],
                        userRole: row[2],
                        userType: row[3],
                        userWf: row[4],
                        userPrivilege: row[5],
                        start: row[6],
                        end: row[7],
                    });
                }
                if (row[8]) {
                    systemSpecs.channel.push({
                        channelId: row[8],
                        channelName: row[9],
                        channelType: row[10],
                        channelWf: row[11],
                        start: row[12],
                        end: row[13],
                    });
                }
                if (row[14]) {
                    systemSpecs.resource.push({
                        resourceId: row[14],
                        resourceName: row[15],
                        resourceType: row[16],
                        resourceWf: row[17],
                        start: row[18],
                        end: row[18],
                    });
                }
            }
        });
    });
    readXlsxFile(input.files[0], { sheet: 2 }).then(function (rows) { // reads the sheet corresponding to the attacks
        listOfAttacks = rows;
        listOfAttacks.forEach((attack, index) => {
            if (index > 2) {
                attackSpecs.push({
                    code: attack[0],
                    description: attack[1],
                    resource: {
                        elements: attack[2].split(",").map(point => point.split(":")),
                        start: attack[3].split(", ").map(point => Number(point.split(":")[0])),
                        end: attack[3].split(", ").map(point => Number(point.split(":")[1])),
                    },
                    channel: {
                        elements: attack[4].split(",").map(point => point.split(":")),
                        start: attack[5].split(", ").map(point => Number(point.split(":")[0])),
                        end: attack[5].split(", ").map(point => Number(point.split(":")[1])),
                    },
                    user: {
                        elements: attack[6].split(",").map(point => point.split(":")),
                        start: attack[7].split(", ").map(point => Number(point.split(":")[0])),
                        end: attack[7].split(", ").map(point => Number(point.split(":")[1])),
                    },
                });
            }
        });
    });
    readXlsxFile(input.files[0], { sheet: 3 }).then(function (rows) { //reads the sheet corresponding to the countermeasures
        listOfCountermeasures = rows;
        listOfCountermeasures.forEach((countermeasure, index) => {
            if (index > 2) {
                countermeasuresSpecs.push({
                    code: countermeasure[0],
                    description: countermeasure[1],
                    resource: {
                        elements: countermeasure[2].split(",").map(point => point.split(":")),
                        start: countermeasure[3].split(", ").map(point => Number(point.split(":")[0])),
                        end: countermeasure[3].split(", ").map(point => Number(point.split(":")[1])),
                    },
                    channel: {
                        elements: countermeasure[4].split(",").map(point => point.split(":")),
                        start: countermeasure[5].split(", ").map(point => Number(point.split(":")[0])),
                        end: countermeasure[5].split(", ").map(point => Number(point.split(":")[1])),
                    },
                    user: {
                        elements: countermeasure[6].split(",").map(point => point.split(":")),
                        start: countermeasure[7].split(", ").map(point => Number(point.split(":")[0])),
                        end: countermeasure[7].split(", ").map(point => Number(point.split(":")[1])),
                    },
                });
            }
        });
    });
    button.disabled = !(detrimentalEventSelected && mitigationActionSelected && document.getElementById("excelFile").files[0]);
}
