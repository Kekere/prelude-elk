var xmlContent = "";
var organizations = [], equipment = [], countermeasures = [], risk_mitigations = [], annual_response_mitigations = [], annual_response_costs = [], incidents = [], annual_loss_expectancies = [];

document.addEventListener("DOMContentLoaded", function () {
    checkJsonExists();
});