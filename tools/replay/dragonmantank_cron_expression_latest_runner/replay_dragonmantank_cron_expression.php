<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Cron\CronExpression;
use Cron\DayOfMonthField;
use Cron\DayOfWeekField;
use Cron\HoursField;
use Cron\MinutesField;
use Cron\MonthField;

function stable_json($value): string
{
    return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
}

function read_payload(array $argv)
{
    $path = null;
    foreach (array_slice($argv, 1) as $arg) {
        if ($arg !== '--fill' && $arg !== '--mutant') {
            $path = $arg;
            break;
        }
    }
    $text = $path ? file_get_contents($path) : stream_get_contents(STDIN);
    if ($text === false || trim($text) === '') {
        fwrite(STDERR, "missing JSON payload\n");
        exit(2);
    }
    $payload = json_decode($text, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        fwrite(STDERR, "invalid JSON: " . json_last_error_msg() . "\n");
        exit(2);
    }
    return $payload;
}

function parse_time($value, ?string $timezone = null): DateTimeInterface
{
    $tz = $timezone === null ? null : new DateTimeZone($timezone);
    if (is_array($value) && isset($value['local'], $value['timezone'])) {
        return new DateTimeImmutable((string) $value['local'], new DateTimeZone((string) $value['timezone']));
    }
    if ($value === null) {
        return new DateTimeImmutable('now', $tz);
    }
    if (is_int($value) || is_float($value)) {
        $dt = new DateTimeImmutable('@' . (string) $value);
        return $tz ? $dt->setTimezone($tz) : $dt;
    }
    return new DateTimeImmutable((string) $value, $tz);
}

function fmt(DateTimeInterface $dt, bool $withZone = false): string
{
    return $withZone ? $dt->format('Y-m-d\TH:i:sP e') : $dt->format('Y-m-d\TH:i:sP');
}

function field_for(string $field)
{
    return match ($field) {
        'minute' => new MinutesField(),
        'hour' => new HoursField(),
        'day_of_month' => new DayOfMonthField(),
        'month' => new MonthField(),
        'day_of_week' => new DayOfWeekField(),
        default => throw new InvalidArgumentException("unsupported field $field"),
    };
}

function canonicalize($value)
{
    if (is_array($value)) {
        $isList = array_keys($value) === range(0, count($value) - 1);
        if ($isList) {
            return array_map('canonicalize', $value);
        }
        ksort($value);
        foreach ($value as $key => $item) {
            $value[$key] = canonicalize($item);
        }
    }
    return $value;
}

function mutate_value($value)
{
    if (is_bool($value)) {
        return !$value;
    }
    if (is_int($value)) {
        return $value + 1;
    }
    if (is_float($value)) {
        return $value + 1.0;
    }
    if (is_string($value)) {
        if (preg_match('/\d/', $value) === 1) {
            return preg_replace_callback('/\d+/', static fn ($m) => (string) (((int) $m[0]) + 1), $value, 1);
        }
        return $value . '__mutant';
    }
    if (is_array($value)) {
        if (count($value) === 0) {
            return ['__mutant'];
        }
        $copy = $value;
        $keys = array_keys($copy);
        $first = $keys[0];
        $copy[$first] = mutate_value($copy[$first]);
        return $copy;
    }
    return '__mutant';
}

function run_contract(array $contract): array
{
    $params = $contract['params'] ?? [];
    $op = $contract['op'] ?? '';
    try {
        if ($op === 'parse') {
            $cron = new CronExpression((string) $params['expression']);
            return [
                'expression' => $cron->getExpression(),
                'parts' => $cron->getParts(),
                'string' => (string) $cron,
                'missingPart' => $cron->getExpression('missing'),
            ];
        }
        if ($op === 'get_parts') {
            $cron = new CronExpression((string) $params['expression']);
            return ['parts' => $cron->getParts()];
        }
        if ($op === 'set_expression') {
            $cron = new CronExpression((string) $params['initial']);
            $cron->setExpression((string) $params['expression']);
            return ['expression' => $cron->getExpression(), 'parts' => $cron->getParts()];
        }
        if ($op === 'set_part') {
            $cron = new CronExpression((string) $params['initial']);
            $cron->setPart((int) $params['position'], (string) $params['value']);
            return ['expression' => $cron->getExpression(), 'parts' => $cron->getParts()];
        }
        if ($op === 'is_valid') {
            return ['value' => CronExpression::isValidExpression((string) $params['expression'])];
        }
        if ($op === 'is_due') {
            $cron = new CronExpression((string) $params['expression']);
            $timezone = $params['timezone'] ?? null;
            $dt = parse_time($params['date'] ?? 'now', $params['date_timezone'] ?? null);
            return ['value' => $cron->isDue($dt, $timezone)];
        }
        if ($op === 'next_run') {
            $cron = new CronExpression((string) $params['expression']);
            if (isset($params['max_iterations'])) {
                $cron->setMaxIterationCount((int) $params['max_iterations']);
            }
            $timezone = $params['timezone'] ?? null;
            $dt = parse_time($params['start'] ?? 'now', $params['date_timezone'] ?? null);
            $out = $cron->getNextRunDate($dt, (int) ($params['nth'] ?? 0), (bool) ($params['allow_current'] ?? false), $timezone);
            return ['date' => fmt($out, (bool) ($params['with_zone_name'] ?? false))];
        }
        if ($op === 'previous_run') {
            $cron = new CronExpression((string) $params['expression']);
            if (isset($params['max_iterations'])) {
                $cron->setMaxIterationCount((int) $params['max_iterations']);
            }
            $timezone = $params['timezone'] ?? null;
            $dt = parse_time($params['start'] ?? 'now', $params['date_timezone'] ?? null);
            $out = $cron->getPreviousRunDate($dt, (int) ($params['nth'] ?? 0), (bool) ($params['allow_current'] ?? false), $timezone);
            return ['date' => fmt($out, (bool) ($params['with_zone_name'] ?? false))];
        }
        if ($op === 'multiple_run_dates') {
            $cron = new CronExpression((string) $params['expression']);
            if (isset($params['max_iterations'])) {
                $cron->setMaxIterationCount((int) $params['max_iterations']);
            }
            $timezone = $params['timezone'] ?? null;
            $dt = parse_time($params['start'] ?? 'now', $params['date_timezone'] ?? null);
            $dates = $cron->getMultipleRunDates(
                (int) $params['total'],
                $dt,
                (bool) ($params['invert'] ?? false),
                (bool) ($params['allow_current'] ?? false),
                $timezone
            );
            return ['dates' => array_map(static fn ($d) => fmt($d, (bool) ($params['with_zone_name'] ?? false)), $dates)];
        }
        if ($op === 'parse_error') {
            try {
                $cron = new CronExpression((string) ($params['expression'] ?? '* * * * *'));
                if (($params['action'] ?? '') === 'set_part') {
                    $cron->setPart((int) $params['position'], (string) $params['value']);
                } elseif (($params['action'] ?? '') === 'set_expression') {
                    $cron->setExpression((string) $params['value']);
                } elseif (($params['action'] ?? '') === 'next') {
                    $cron->getNextRunDate($params['start'] ?? 'now', (int) ($params['nth'] ?? 0));
                }
                return ['error' => false, 'messageContains' => ''];
            } catch (Throwable $error) {
                return ['error' => true, 'messageContains' => $error->getMessage()];
            }
        }
        if ($op === 'field_validate') {
            $field = field_for((string) $params['field']);
            return ['value' => $field->validate((string) $params['value'])];
        }
        if ($op === 'field_satisfied') {
            $field = field_for((string) $params['field']);
            $dt = parse_time($params['date'], $params['date_timezone'] ?? null);
            return ['value' => $field->isSatisfiedBy($dt, (string) $params['value'], (bool) ($params['invert'] ?? false))];
        }
        if ($op === 'field_range') {
            $field = field_for((string) $params['field']);
            return ['range' => $field->getRangeForExpression((string) $params['expression'], (int) $params['max'])];
        }
        if ($op === 'field_increment') {
            $field = field_for((string) $params['field']);
            $dt = new DateTime((string) $params['date'], isset($params['date_timezone']) ? new DateTimeZone((string) $params['date_timezone']) : null);
            $field->increment($dt, (bool) ($params['invert'] ?? false), isset($params['part']) ? (string) $params['part'] : null);
            return ['date' => fmt($dt, (bool) ($params['with_zone_name'] ?? false))];
        }
        if ($op === 'alias_lifecycle') {
            $alias = (string) $params['alias'];
            $expression = (string) $params['expression'];
            if (CronExpression::supportsAlias($alias)) {
                try {
                    CronExpression::unregisterAlias($alias);
                } catch (Throwable $ignored) {
                }
            }
            CronExpression::registerAlias($alias, $expression);
            $registered = CronExpression::supportsAlias($alias);
            $aliasesAfterRegister = CronExpression::getAliases();
            $resolved = (new CronExpression($alias))->getExpression();
            $unregisteredFirst = CronExpression::unregisterAlias($alias);
            $unregisteredSecond = CronExpression::unregisterAlias($alias);
            $supportedAfter = CronExpression::supportsAlias($alias);
            return [
                'registered' => $registered,
                'resolved' => $resolved,
                'aliasValue' => $aliasesAfterRegister[strtolower($alias)] ?? null,
                'unregisteredFirst' => $unregisteredFirst,
                'unregisteredSecond' => $unregisteredSecond,
                'supportedAfter' => $supportedAfter,
            ];
        }
        if ($op === 'alias_error') {
            try {
                if (($params['action'] ?? 'register') === 'unregister') {
                    CronExpression::unregisterAlias((string) $params['alias']);
                } else {
                    CronExpression::registerAlias((string) $params['alias'], (string) $params['expression']);
                }
                return ['error' => false, 'messageContains' => ''];
            } catch (Throwable $error) {
                return ['error' => true, 'messageContains' => $error->getMessage()];
            }
        }
        return ['error' => true, 'messageContains' => "unsupported op $op"];
    } catch (Throwable $error) {
        return ['error' => true, 'messageContains' => $error->getMessage()];
    }
}

function compare_result($actual, $expected): bool
{
    return stable_json(canonicalize($actual)) === stable_json(canonicalize($expected));
}

$payload = read_payload($argv);
$fill = in_array('--fill', $argv, true);
$mutant = in_array('--mutant', $argv, true);
$isList = is_array($payload) && array_keys($payload) === range(0, count($payload) - 1);
$contracts = $isList ? $payload : [$payload];
$results = [];
$passed = 0;

foreach ($contracts as $contract) {
    $actual = run_contract($contract);
    if ($fill) {
        $contract['expected'] = $actual;
        $results[] = $contract;
        continue;
    }
    $expected = $contract['expected'] ?? null;
    if ($mutant) {
        $mutated = mutate_value($expected);
        $ok = !compare_result($actual, $mutated);
    } else {
        $ok = compare_result($actual, $expected);
    }
    if ($ok) {
        ++$passed;
    }
    $results[] = [
        'name' => $contract['name'] ?? null,
        'ok' => $ok,
        'actual' => $actual,
        'expected' => $mutant ? mutate_value($expected) : $expected,
    ];
}

if ($fill) {
    echo stable_json($isList ? $results : $results[0]) . PHP_EOL;
    exit(0);
}

echo stable_json([
    'ok' => $passed === count($contracts),
    'passed' => $passed,
    'total' => count($contracts),
    'mode' => $mutant ? 'mutant' : 'replay',
    'results' => $results,
]) . PHP_EOL;
exit($passed === count($contracts) ? 0 : 1);
