var xmlContent = ""; //, jsonString = "";
var organizations = [], equipment = [], countermeasures = [], risk_mitigations = [], annual_response_costs = [], incidents = [], annual_loss_expectancies = []; //might need to tune for each object alone or each page

function extract() {
    let myRORIObject = JSON.parse(localStorage.getItem("RORIString"));
    organizations = myRORIObject.organizations ? myRORIObject.organizations : [];
    equipment = myRORIObject.equipment ? myRORIObject.equipment : [];
    countermeasures = myRORIObject.countermeasures ? myRORIObject.countermeasures : [];
    risk_mitigations = myRORIObject.risk_mitigations ? myRORIObject.risk_mitigations : [];
    annual_response_costs = myRORIObject.annual_response_costs ? myRORIObject.annual_response_costs : [];
    incidents = myRORIObject.incidents ? myRORIObject.incidents : [];
    annual_loss_expectancies = myRORIObject.annual_loss_expectancies ? myRORIObject.annual_loss_expectancies : [];
}

function checkJsonExists() {
    let jsonExists = false;
    if (localStorage.getItem("RORIString")) {
        jsonExists = true;
    }
    if (document.getElementById("xmlExists")) { //check if label exists in the web page (when in homepage)
        if (jsonExists) {
            document.getElementById("xmlExists").innerHTML = "Using existing XML file. You can still upload a new one! ";
        } else {
            document.getElementById("xmlExists").innerHTML = "Missing or invalid XML file! Please upload one. ";
        }
    }
}

function saveXmlAsJsonString(input) {
    let fileReader = new FileReader();
    fileReader.readAsText(input.files[0]);
    fileReader.onload = function () {
        xmlContent = fileReader.result;
        if (validateXML(xmlContent)) {
            let temp = convertXmlToJson(xmlContent);
            saveRORI(temp.RORI[0]);
            window.location.reload();
        }
    };
    fileReader.onerror = function () {
        alert("Error Reading XML File: " + fileReader.error);
        window.location.reload();
    };
}

/**
 * Converts XML formatted String to a JSON object.
 * @param {String} xmlData - XML Formatted String.
 * @returns {} jsonObject
 */
function convertXmlToJson(xmlString) {
    let options = { //options to be passed to the xml parser
        attributeNamePrefix: "",
        attrNodeName: false,
        textNodeName: "#text",
        ignoreAttributes: false,
        ignoreNameSpace: false,
        allowBooleanAttributes: true,
        parseNodeValue: true,
        parseAttributeValue: true,
        trimValues: true,
        cdataTagName: false,
        cdataPositionChar: "\\c",
        parseTrueNumberOnly: false,
        arrayMode: true, // or false
        attrValueProcessor: a => a,
        tagValueProcessor: a => a,
        stopNodes: ["parse-me-as-string"]
    };
    let tObj = parser.getTraversalObj(xmlString, options); // intermediate obj
    return parser.convertToJson(tObj, options);
}

function saveRORI(json) {
    organizations = json.ORGANIZATIONS[0].organization;
    equipment = json.EQUIPMENTS[0].equipment;
    countermeasures = json.COUNTERMEASURES[0].countermeasure;
    risk_mitigations = json.RISK_MITIGATION[0].rm;
    annual_response_costs = json.ANNUAL_RESPONSE_COST[0].arc;
    incidents = json.INCIDENTS[0].incident;
    annual_loss_expectancies = json.ANNUAL_LOSS_EXPECTANCY[0].ale;

    let organization = organizations[0];
    let organizationEquipment = [];
    organization.AEV = [];
    if (String(typeof organization.id_equipments) == "number") {
        organizationEquipment.push(organization.id_equipments);
    }
    else if (organization.id_equipments.length != 0) {
        organizationEquipment = organization.id_equipments.split(",").map(Number);
    }
    organizationEquipment.forEach(orgEq => {
        equipment.forEach(eq => {
            if (orgEq == eq.id) {
                organization.AEV.push({
                    equipmentId: eq.id,
                    organizationId: organization.id,
                    AEV: eq.AEV
                });
            }
        });
    });
    let RORIString = {
        organizations: organizations,
        equipment: equipment,
        countermeasures: countermeasures,
        risk_mitigations: risk_mitigations,
        annual_response_costs: annual_response_costs,
        incidents: incidents,
        annual_loss_expectancies: annual_loss_expectancies,
    };
    localStorage.setItem("RORIString", JSON.stringify(RORIString));
}

/**
 * Used to go back.
 */
function goBack() {
    window.history.back();
}

/**
 * Clears the contents of a given table.
 * @param {*} table 
 */
function clearTable(table) {
    while (table.hasChildNodes()) {
        table.removeChild(table.firstChild);
    }
}

/**
 * Alerts user when navigating with a missing XML file.
 */
function xmlAlert() {
    alert("Missing or invalid XML file!");
}

/**
 * Start of xml file validation
 */
var xt = "",
    h3OK = 1;

function checkErrorXML(x) {
    xt = "";
    h3OK = 1;
    checkXML(x);
}

function checkXML(n) {
    let l, i, nam;
    nam = n.nodeName;
    if (nam == "h3") {
        if (h3OK == 0) {
            return;
        }
        h3OK = 0;
    }
    if (nam == "#text") {
        xt = xt + n.nodeValue + "\n";
    }
    l = n.childNodes.length;
    for (i = 0; i < l; i++) {
        checkXML(n.childNodes[i]);
    }
}

/**
 * Takes a String representation of an xml file and returns a true if valid
 * @param {*} txt - XML Formatted String.
 * @returns {Boolean} valid XML.
 */
function validateXML(txt) {
    // code for IE
    let xmlDoc;
    if (window.ActiveXObject) {
        xmlDoc = new ActiveXObject("Microsoft.XMLDOM");
        xmlDoc.async = false;
        xmlDoc.loadXML(document.all(txt).value);
        if (xmlDoc.parseError.errorCode != 0) {
            txt = "Error Code: " + xmlDoc.parseError.errorCode + "\n";
            txt = txt + "Error Reason: " + xmlDoc.parseError.reason;
            txt = txt + "Error Line: " + xmlDoc.parseError.line;
            alert(txt);
            return false;
        } else {
            return true;
        }
    }
    // code for Mozilla, Firefox, Opera, etc.
    else if (document.implementation.createDocument) {
        try {
            let parser = new DOMParser();
            xmlDoc = parser.parseFromString(txt, "application/xml");
        } catch (err) {
            alert(err.message);
            return false;
        }
        if (xmlDoc.getElementsByTagName("parsererror").length > 0) {
            checkErrorXML(xmlDoc.getElementsByTagName("parsererror")[0]);
            alert(xt);
            return false;
        } else {
            return true;
        }
    }
    else {
        alert('Your browser cannot handle XML validation');
        return false;
    }
}
/**
 * End of xml file Validation
 */

var _cf = (function () {
    function _shift(x) {
        var parts = x.toString().split('.');
        return (parts.length < 2) ? 1 : Math.pow(10, parts[1].length);
    }
    return function () {
        return Array.prototype.reduce.call(arguments, function (prev, next) { return prev === undefined || next === undefined ? undefined : Math.max(prev, _shift(next)); }, -Infinity);
    };
})();

Math.a = function () {
    var f = _cf.apply(null, arguments); if (f === undefined) return undefined;
    function cb(x, y, i, o) { return x + f * y; }
    return Array.prototype.reduce.call(arguments, cb, 0) / f;
};

Math.s = function (l, r) { var f = _cf(l, r); return (l * f - r * f) / f; };

Math.m = function () {
    var f = _cf.apply(null, arguments);
    function cb(x, y, i, o) { return (x * f) * (y * f) / (f * f); }
    return Array.prototype.reduce.call(arguments, cb, 1);
};

Math.d = function (l, r) { var f = _cf(l, r); return (l * f) / (r * f); };

function saveToXML() {
    if (localStorage.getItem("RORIString")) {
        let RORIObject = JSON.parse(localStorage.getItem("RORIString"));
        extract();
        if (RORIObject.organizations.length !== 1) {
            alert("Please make sure there is only one organization.");
            return;
        }
        let Builder = parser.j2xParser;
        let options = {
            attributeNamePrefix: "",
            attrNodeName: "",
            textNodeName: "#text",
            ignoreAttributes: false,
            cdataTagName: false,
            cdataPositionChar: "\\c",
            format: true,
            indentBy: "  ",
            arrayMode: true,
            tagValueProcessor: a => a,
            attrValueProcessor: a => a,
        };
        let ORGANIZATIONS = [], EQUIPMENTS = [], COUNTERMEASURES = [], RISK_MITIGATION = [], ANNUAL_RESPONSE_COST = [], INCIDENTS = [], ANNUAL_LOSS_EXPECTANCY = [];
        RORIObject.organizations[0].AEV.forEach(aev => {
            RORIObject.equipment.forEach(eq => {
                if (aev.equipmentId == eq.id) {
                    equipment.AEV = aev.AEV;
                }
            });
        });
        delete RORIObject.organizations[0].AEV;
        ORGANIZATIONS.push({ organization: RORIObject.organizations });
        EQUIPMENTS.push({ equipment: equipment });
        COUNTERMEASURES.push({ countermeasure: RORIObject.countermeasures });
        RISK_MITIGATION.push({ rm: RORIObject.risk_mitigations });
        ANNUAL_RESPONSE_COST.push({ arc: RORIObject.annual_loss_expectancies });
        INCIDENTS.push({ incident: RORIObject.incidents });
        ANNUAL_LOSS_EXPECTANCY.push({ ale: RORIObject.annual_loss_expectancies });
        let RORI = {
            ORGANIZATIONS: ORGANIZATIONS,
            EQUIPMENTS: EQUIPMENTS,
            COUNTERMEASURES: COUNTERMEASURES,
            RISK_MITIGATION: RISK_MITIGATION,
            ANNUAL_RESPONSE_COST: ANNUAL_RESPONSE_COST,
            INCIDENTS: INCIDENTS,
            ANNUAL_LOSS_EXPECTANCY: ANNUAL_LOSS_EXPECTANCY,
        };
        let xmlParser = new Builder(options);
        let xml = xmlParser.parse({ RORI: RORI });
        let file = new File([xml], "Modifications.xml", { type: "application/xml; charset=utf-8" });
        saveAs(file);
    }
    else {
        alert("No data to be saved.");
    }
}