import { describe, expect, it } from 'vitest';
import { ageInDays, bumpType, isInQuarantine, isVulnerable, vulnerabilityCounts } from '../../src/core/resolver/versions';
import { advisory, FIXTURE_NOW } from './helpers';

describe('bumpType', () => {
  it('clasifica patch, minor y major', () => {
    expect(bumpType('1.18.0', '1.18.3')).toBe('patch');
    expect(bumpType('1.18.0', '1.20.0')).toBe('minor');
    expect(bumpType('8.5.1', '9.0.0')).toBe('major');
  });

  it('en 0.x un cambio de minor rompe como un major', () => {
    expect(bumpType('0.21.5', '0.25.0')).toBe('major');
    expect(bumpType('0.21.5', '0.21.9')).toBe('patch');
    expect(bumpType('0.0.1', '0.0.2')).toBe('major');
  });
});

describe('isVulnerable', () => {
  const list = [advisory('>=1.0.0 <1.20.0'), advisory('<=0.5.0', 'moderate')];

  it('compara contra todos los rangos', () => {
    expect(isVulnerable('1.19.9', list)).toBe(true);
    expect(isVulnerable('1.20.0', list)).toBe(false);
    expect(isVulnerable('0.4.0', list)).toBe(true);
  });

  it('trata un rango ilegible como vulnerable para todas las versiones', () => {
    expect(isVulnerable('99.0.0', [advisory('not a range')])).toBe(true);
  });

  it('cuenta vulnerabilidades por severidad para una versión', () => {
    expect(vulnerabilityCounts('0.4.0', list)).toMatchObject({ high: 0, moderate: 1 });
    expect(vulnerabilityCounts('1.10.0', list)).toMatchObject({ high: 1, moderate: 0 });
  });
});

describe('cuarentena', () => {
  it('calcula la antigüedad en días', () => {
    expect(ageInDays('2026-10-27T12:00:00Z', FIXTURE_NOW)).toBe(3);
    expect(ageInDays(undefined, FIXTURE_NOW)).toBeUndefined();
  });

  it('pone en cuarentena lo reciente y lo que no tiene fecha', () => {
    expect(isInQuarantine(3, 7)).toBe(true);
    expect(isInQuarantine(7, 7)).toBe(false);
    expect(isInQuarantine(undefined, 7)).toBe(true);
    expect(isInQuarantine(undefined, 0)).toBe(false);
  });
});
