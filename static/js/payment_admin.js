document.addEventListener("DOMContentLoaded", function () {
    var coinField = document.querySelector("#id_coin");
    var networkField = document.querySelector("#id_network");

    var networkOptions = {
        "BTC": ["Bitcoin", "Lightening"],
        "ETH": ["ERC20", "BEP20"],
        "USDT": ["TRC20", "ERC20"],
        "LTC": ["Lightcoin"],
    };

    function updateNetworkChoices() {
        var selectedCoin = coinField.value;
        networkField.innerHTML = "";
        networkField.disabled = false;

        if (networkOptions[selectedCoin]) {
            networkOptions[selectedCoin].forEach(function (network) {
                var option = document.createElement("option");
                option.value = network;
                option.textContent = network;
                networkField.appendChild(option);
            });
        }
    }

    coinField.addEventListener("change", updateNetworkChoices);
    updateNetworkChoices();  // Run on page load in case of existing values
});
