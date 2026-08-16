// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {DeployZkSelfIssuance} from "../script/DeployZkSelfIssuance.s.sol";

contract DeployZkSelfIssuanceTest is Test {
    DeployZkSelfIssuance internal script;

    function setUp() public {
        script = new DeployZkSelfIssuance();
    }

    function test_OnlyDocumentedTestnetsAndLocalRehearsalAreAccepted() public view {
        assertTrue(script.supportedTestnet(31_337));
        assertTrue(script.supportedTestnet(84_532));
        assertTrue(script.supportedTestnet(11_155_111));
        assertTrue(script.supportedTestnet(11_142_220));
        assertTrue(script.supportedTestnet(46_630));
        assertTrue(script.supportedTestnet(4_801));

        assertFalse(script.supportedTestnet(1));
        assertFalse(script.supportedTestnet(8_453));
        assertFalse(script.supportedTestnet(42_220));
        assertFalse(script.supportedTestnet(480));
        assertFalse(script.supportedTestnet(4_663));
    }
}
