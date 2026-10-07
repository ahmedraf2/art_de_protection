// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title GradeLedger — integrity ledger for grades and certificates.
/// @notice Stores only SHA-256 hashes (never names or grades). The app keeps the
///         real records in SQLite; this contract is the independent reference it
///         compares them against. Only the issuer's key can write here.
contract GradeLedger {
    /// The only account allowed to write. Fixed forever at deployment.
    address public immutable issuer;

    /// Latest grade hash per (courseId => studentId => hash).
    mapping(uint256 => mapping(uint256 => bytes32)) private grades;

    /// Certificate fingerprints that were anchored by the issuer.
    mapping(bytes32 => bool) private certificates;

    event GradeAnchored(address indexed sender, uint256 indexed courseId,
                        uint256 indexed studentId, bytes32 gradeHash);
    event CertificateAnchored(address indexed sender, bytes32 indexed fingerprint);

    error NotIssuer();

    constructor() {
        issuer = msg.sender;            // whoever deploys the contract is the issuer
    }

    /// SECURE: the key security point — every write function checks the caller.
    /// Without this, anyone with an Ethereum account could forge records.
    modifier onlyIssuer() {
        if (msg.sender != issuer) revert NotIssuer();
        _;
    }

    /// Record (or update) the hash of a student's grade in a course.
    function anchorGrade(uint256 courseId, uint256 studentId, bytes32 gradeHash)
        external onlyIssuer
    {
        grades[courseId][studentId] = gradeHash;
        emit GradeAnchored(msg.sender, courseId, studentId, gradeHash);
    }

    /// The latest anchored grade hash (0x00… if none).
    function getGrade(uint256 courseId, uint256 studentId) external view returns (bytes32) {
        return grades[courseId][studentId];
    }

    /// Record that a certificate with this fingerprint was genuinely issued.
    function anchorCertificate(bytes32 fingerprint) external onlyIssuer {
        certificates[fingerprint] = true;
        emit CertificateAnchored(msg.sender, fingerprint);
    }

    function isCertificateAnchored(bytes32 fingerprint) external view returns (bool) {
        return certificates[fingerprint];
    }
}
