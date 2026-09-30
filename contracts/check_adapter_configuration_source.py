#!/usr/bin/env python3
"""Portable wiring/policy-copy gates. These do NOT compile or execute Swift.

Use --ref <commit> to check a historical source tree with the same assertions.
The native behavior suite remains check_local_assessment.py on macOS.
"""
import argparse
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'RiskDetectorApp/Sources/CloudPhoneRiskKit/'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--ref')
args = parser.parse_args()


def read(path):
    if args.ref:
        return subprocess.check_output(['git', 'show', f'{args.ref}:{SOURCE}{path}'], cwd=ROOT, text=True)
    return (ROOT / SOURCE / path).read_text()


def require(condition, message):
    if not condition:
        raise SystemExit('Adapter configuration source gate FAIL: ' + message)


adapter = read('LocalAssessment/LocalAssessmentAdapter.swift')
engine = read('LocalAssessment/RiskDetectionEngine.swift')
scenario = read('LocalAssessment/ScenarioPolicy.swift')
result = read('LocalAssessment/LocalAssessment.swift')
tree = read('LocalAssessment/DecisionTree.swift')
require(adapter.count('assessLocally(snapshot: snapshot, config: config, policy:') == 2,
        'async and sync must share local configuration application')
require('.selectingDetectorFamilies(config.enabledDetectors)' in adapter, 'detector selection must reach engine')
require(').retainingLocalExtras(config.extras)' in adapter, 'local metadata must reach result')
require('high.isFinite' in adapter and 'base.mediumThreshold < high, high < base.criticalThreshold' in adapter,
        'high threshold must be finite and retain ordered neighbors')

# New policy fields must not be silently lost when this explicit immutable copy evolves.
for source, struct, prefix, exceptions in [
    (engine, 'EnginePolicy', 'policy', {'scenarioPolicies'}),
    (scenario, 'ScenarioPolicy', 'base', {'highThreshold'}),
]:
    fields = source.split(f'public struct {struct}:', 1)[1].split('private enum CodingKeys', 1)[0]
    for field in re.findall(r'public let (\w+):', fields):
        if field not in exceptions:
            require(f'{field}: {prefix}.{field}' in adapter, f'{struct}.{field} must survive copy')

selection = engine.split('private func detectorEnabled(', 1)[1].split('private func includeSelectedSignal', 1)[0]
require('policy.' not in selection, 'selection must not change existing policy/provider semantics')
require('families.isEmpty ? DecisionConfig.defaultDetectors : families' in engine, 'normalize empty selection')
require('provider(context).filter(includeSelectedSignal)' in engine, 'filter provider evidence before fusion')
require('signal.state == .tampered || detectorEnabled(signal.category)' in engine, 'retain explicit integrity failures')
require('if context.jailbreak.isJailbroken' not in engine, 'ungated jailbreak context path')
require('context.riskContext.jailbreak.isJailbroken' not in tree, 'ungated tree jailbreak path')
require('context.riskContext.network.' not in tree, 'ungated tree network path')
require('evaluationContext.jailbreakEnabled = detectorEnabled(' in engine, 'tree must receive jailbreak selection')
require('evaluationContext.networkEnabled = detectorEnabled(' in engine, 'tree must receive network selection')
require('result.enabledDetectorFamilies = enabledDetectorFamilies' in engine, 'policy replacement must preserve selection')
require('enableLogging: enableLogging' in engine and 'customProviders: customProviders' in engine,
        'policy replacement must preserve PR92 state')

coding_keys = result.split('private enum CodingKeys', 1)[1].split('// MARK:', 1)[0]
encoding = result.split('public func encode(to encoder:', 1)[1].split('///', 1)[0]
require('localConfigurationExtras' not in coding_keys + encoding, 'caller metadata must not enter result transport')
require('var result = self' in result and 'result.localConfigurationExtras = extras' in result,
        'metadata attachment must preserve assessment identity')
print('Adapter configuration source gates: PASS (static only; Swift behavior not executed)')
