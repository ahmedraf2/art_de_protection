// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GradeLedger} from "../src/GradeLedger.sol";
import {vm} from "./Vm.sol";

/// Run with:  cd contracts && forge test -vv
/// A function named test* passes unless it reverts.
contract GradeLedgerTest {
    GradeLedger ledger;
    address attacker = address(0xBAD);

    function setUp() public {
        ledger = new GradeLedger();     // this test contract is the issuer
    }

    function test_IssuerCanAnchorGrade() public {
        bytes32 h = sha256("course 1, student 4, grade 14.00");
        ledger.anchorGrade(1, 4, h);
        require(ledger.getGrade(1, 4) == h, "grade hash not stored");
    }

    function test_NonIssuerReverts() public {
        // compute hashes first: sha256() is itself a call and would use up the prank
        bytes32 forgedGrade = sha256("forged 20.00");
        bytes32 fakeCert = sha256("fake PhD");

        vm.prank(attacker);
        vm.expectRevert(GradeLedger.NotIssuer.selector);
        ledger.anchorGrade(1, 4, forgedGrade);

        vm.prank(attacker);
        vm.expectRevert(GradeLedger.NotIssuer.selector);
        ledger.anchorCertificate(fakeCert);

        require(ledger.getGrade(1, 4) == bytes32(0), "forged grade was stored");
    }

    function test_CertificateLookup() public {
        bytes32 real = sha256("Python Developer");
        ledger.anchorCertificate(real);
        require(ledger.isCertificateAnchored(real), "real cert not found");
        require(!ledger.isCertificateAnchored(sha256("fake PhD")), "fake cert found");
    }
}
