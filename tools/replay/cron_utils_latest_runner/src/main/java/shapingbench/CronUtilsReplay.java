package shapingbench;

import com.cronutils.builder.CronBuilder;
import com.cronutils.descriptor.CronDescriptor;
import com.cronutils.mapper.ConstantsMapper;
import com.cronutils.mapper.CronMapper;
import com.cronutils.mapper.WeekDay;
import com.cronutils.model.Cron;
import com.cronutils.model.CronType;
import com.cronutils.model.definition.CronConstraintsFactory;
import com.cronutils.model.definition.CronDefinition;
import com.cronutils.model.definition.CronDefinitionBuilder;
import com.cronutils.model.time.ExecutionTime;
import com.cronutils.parser.CronParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import java.time.Duration;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static com.cronutils.model.field.expression.FieldExpression.questionMark;
import static com.cronutils.model.field.expression.FieldExpressionFactory.always;
import static com.cronutils.model.field.expression.FieldExpressionFactory.every;
import static com.cronutils.model.field.expression.FieldExpressionFactory.on;

public class CronUtilsReplay {
    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    public static void main(String[] args) throws Exception {
        boolean fill = false;
        String inputPath = null;
        for (String arg : args) {
            if ("--fill".equals(arg)) {
                fill = true;
            } else {
                inputPath = arg;
            }
        }
        JsonNode root = inputPath == null ? JSON.readTree(System.in) : JSON.readTree(new File(inputPath));
        List<Map<String, Object>> rows = root.isArray()
                ? JSON.convertValue(root, new TypeReference<>() {})
                : JSON.convertValue(root.get("contracts"), new TypeReference<>() {});

        if (fill) {
            List<Map<String, Object>> contracts = new ArrayList<>();
            for (Map<String, Object> contract : rows) {
                Map<String, Object> copy = new LinkedHashMap<>(contract);
                Map<String, Object> actual = run(contract);
                copy.put("expected", actual);
                copy.put("mutant", mutateExpected(actual));
                contracts.add(copy);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("contracts", contracts);
            JSON.writeValue(System.out, out);
            return;
        }

        List<Map<String, Object>> results = new ArrayList<>();
        for (Map<String, Object> contract : rows) {
            Map<String, Object> actual = run(contract);
            Map<String, Object> expected = getMap(contract, "expected");
            Map<String, Object> mutant = getMap(contract, "mutant");
            boolean replayPassed = matches(expected, actual);
            boolean mutantPassed = replayPassed && matches(mutant, actual);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("name", contract.get("name"));
            result.put("version", contract.get("version"));
            result.put("capability", contract.get("capability"));
            result.put("op", contract.get("op"));
            result.put("status", replayPassed && !mutantPassed ? "passed" : "failed");
            result.put("replay_passed", replayPassed);
            result.put("mutant_rejected", replayPassed && !mutantPassed);
            result.put("expected", expected);
            result.put("mutant", mutant);
            result.put("actual", actual);
            results.add(result);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("results", results);
        JSON.writeValue(System.out, out);
    }

    private static Map<String, Object> run(Map<String, Object> contract) {
        try {
            String op = String.valueOf(contract.get("op"));
            Map<String, Object> params = getMap(contract, "params");
            if ("parse_as_string".equals(op)) {
                return one("string", parse(params).asString());
            }
            if ("parse_valid".equals(op)) {
                parse(params).validate();
                return one("value", true);
            }
            if ("cross_next_dates".equals(op) || "cross_prev_dates".equals(op) || "cross_match".equals(op)
                    || "cross_range_dates".equals(op) || "cross_parse_valid".equals(op)
                    || "cross_parse_error".equals(op) || "cross_parse_normalize".equals(op)
                    || "cross_count_executions".equals(op)) {
                return runCross(op, params);
            }
            if ("parse_error".equals(op)) {
                try {
                    parse(params).validate();
                    return one("error", false);
                } catch (Exception error) {
                    return errorResult(error);
                }
            }
            if ("describe".equals(op)) {
                Cron cron = parse(params);
                Locale locale = locale(String.valueOf(params.getOrDefault("locale", "en-GB")));
                return one("description", CronDescriptor.instance(locale).describe(cron));
            }
            if ("map".equals(op)) {
                Cron mapped = mapper(String.valueOf(params.get("mapper"))).map(parse(params));
                return one("string", mapped.asString());
            }
            if ("equivalent".equals(op)) {
                Cron left = parseTyped(String.valueOf(params.get("leftType")), String.valueOf(params.get("left")));
                Cron right = parseTyped(String.valueOf(params.get("rightType")), String.valueOf(params.get("right")));
                if (params.containsKey("mapper")) {
                    return one("value", left.equivalent(mapper(String.valueOf(params.get("mapper"))), right));
                }
                return one("value", left.equivalent(right));
            }
            if ("next_execution".equals(op) || "last_execution".equals(op) || "execution_dates".equals(op)
                    || "time_to_next".equals(op) || "time_from_last".equals(op) || "is_match".equals(op)
                    || "count_executions".equals(op)) {
                return runExecution(op, params);
            }
            if ("builder_predefined".equals(op)) {
                CronDefinition definition = definitionFor(params);
                String name = String.valueOf(params.get("builder"));
                Cron cron = switch (name) {
                    case "yearly" -> CronBuilder.yearly(definition);
                    case "annually" -> CronBuilder.annually(definition);
                    case "monthly" -> CronBuilder.monthly(definition);
                    case "weekly" -> CronBuilder.weekly(definition);
                    case "daily" -> CronBuilder.daily(definition);
                    case "midnight" -> CronBuilder.midnight(definition);
                    case "hourly" -> CronBuilder.hourly(definition);
                    case "reboot" -> CronBuilder.reboot(definition);
                    case "custom_month_every" -> CronBuilder.cron(definition)
                            .withMinute(on(((Number) params.getOrDefault("minute", 0)).intValue()))
                            .withHour(on(((Number) params.getOrDefault("hour", 0)).intValue()))
                            .withDoW(questionMark())
                            .withDoM(on(((Number) params.getOrDefault("dayOfMonth", 1)).intValue()))
                            .withDoY(questionMark())
                            .withMonth(every(((Number) params.getOrDefault("every", 1)).intValue()))
                            .instance();
                    case "custom_month_every_from" -> CronBuilder.cron(definition)
                            .withMinute(on(((Number) params.getOrDefault("minute", 0)).intValue()))
                            .withHour(on(((Number) params.getOrDefault("hour", 0)).intValue()))
                            .withDoW(questionMark())
                            .withDoM(on(((Number) params.getOrDefault("dayOfMonth", 1)).intValue()))
                            .withDoY(questionMark())
                            .withMonth(every(on(((Number) params.getOrDefault("month", 1)).intValue()), ((Number) params.getOrDefault("every", 1)).intValue()))
                            .instance();
                    case "custom_weekly" -> CronBuilder.cron(definition)
                            .withMinute(on(((Number) params.getOrDefault("minute", 0)).intValue()))
                            .withHour(on(((Number) params.getOrDefault("hour", 0)).intValue()))
                            .withDoW(on(((Number) params.getOrDefault("dayOfWeek", 1)).intValue()))
                            .withDoM(questionMark())
                            .withDoY(questionMark())
                            .withMonth(always())
                            .withYear(always())
                            .instance();
                    default -> throw new IllegalArgumentException("unsupported builder " + name);
                };
                return one("string", cron.asString());
            }
            if ("weekday_map".equals(op)) {
                WeekDay source = weekday(String.valueOf(params.get("source")));
                WeekDay target = weekday(String.valueOf(params.get("target")));
                return one("value", ConstantsMapper.weekDayMapping(source, target, ((Number) params.get("value")).intValue()));
            }
            return errorResult(new IllegalArgumentException("unsupported op " + op));
        } catch (Exception error) {
            return errorResult(error);
        }
    }

    private static Map<String, Object> runExecution(String op, Map<String, Object> params) {
        Cron cron = parse(params);
        ExecutionTime executionTime = ExecutionTime.forCron(cron);
        ZonedDateTime at = zoned(String.valueOf(params.get("at")));
        if ("next_execution".equals(op)) {
            return one("instant", optionalDate(executionTime.nextExecution(at)));
        }
        if ("last_execution".equals(op)) {
            return one("instant", optionalDate(executionTime.lastExecution(at)));
        }
        if ("time_to_next".equals(op)) {
            return one("durationSeconds", optionalDuration(executionTime.timeToNextExecution(at)));
        }
        if ("time_from_last".equals(op)) {
            return one("durationSeconds", optionalDuration(executionTime.timeFromLastExecution(at)));
        }
        if ("is_match".equals(op)) {
            return one("value", executionTime.isMatch(at));
        }
        if ("count_executions".equals(op)) {
            ZonedDateTime end = zoned(String.valueOf(params.get("end")));
            return one("value", executionTime.countExecutions(at, end));
        }
        if ("execution_dates".equals(op)) {
            ZonedDateTime end = zoned(String.valueOf(params.get("end")));
            List<String> dates = executionTime.getExecutionDates(at, end).stream().map(ZonedDateTime::toString).toList();
            return one("dates", dates);
        }
        throw new IllegalArgumentException("unsupported execution op " + op);
    }

    private static Map<String, Object> runCross(String op, Map<String, Object> params) {
        if ("cross_parse_error".equals(op)) {
            try {
                Cron cron = parse(params);
                if (Boolean.TRUE.equals(params.get("use_next"))) {
                    ExecutionTime.forCron(cron).nextExecution(zoned(String.valueOf(params.getOrDefault("start", params.getOrDefault("at", "2024-01-01T00:00:00Z")))));
                }
                return one("error", false);
            } catch (Exception error) {
                return errorResult(error);
            }
        }
        Cron cron = parse(params);
        if ("cross_parse_valid".equals(op)) {
            return one("value", true);
        }
        if ("cross_parse_normalize".equals(op)) {
            return one("string", cron.asString());
        }
        ExecutionTime executionTime = ExecutionTime.forCron(cron);
        if ("cross_next_dates".equals(op)) {
            ZonedDateTime cursor = zoned(String.valueOf(params.getOrDefault("start", params.getOrDefault("at", "2024-01-01T00:00:00Z"))));
            int count = ((Number) params.getOrDefault("count", 1)).intValue();
            List<String> dates = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                Optional<ZonedDateTime> next = executionTime.nextExecution(cursor);
                if (next.isEmpty()) {
                    break;
                }
                cursor = next.get();
                dates.add(cursor.toString());
            }
            return one("dates", dates);
        }
        if ("cross_prev_dates".equals(op)) {
            ZonedDateTime cursor = zoned(String.valueOf(params.getOrDefault("start", params.getOrDefault("at", "2024-01-01T00:00:00Z"))));
            int count = ((Number) params.getOrDefault("count", 1)).intValue();
            List<String> dates = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                Optional<ZonedDateTime> prev = executionTime.lastExecution(cursor);
                if (prev.isEmpty()) {
                    break;
                }
                cursor = prev.get();
                dates.add(cursor.toString());
            }
            return one("dates", dates);
        }
        if ("cross_match".equals(op)) {
            ZonedDateTime at = zoned(String.valueOf(params.getOrDefault("date", params.get("at"))));
            return one("value", executionTime.isMatch(at));
        }
        if ("cross_range_dates".equals(op)) {
            ZonedDateTime start = zoned(String.valueOf(params.get("start")));
            ZonedDateTime end = zoned(String.valueOf(params.getOrDefault("stop", params.get("end"))));
            return one("dates", executionTime.getExecutionDates(start, end).stream().map(ZonedDateTime::toString).toList());
        }
        if ("cross_count_executions".equals(op)) {
            ZonedDateTime start = zoned(String.valueOf(params.get("start")));
            ZonedDateTime end = zoned(String.valueOf(params.getOrDefault("stop", params.get("end"))));
            return one("value", executionTime.countExecutions(start, end));
        }
        return errorResult(new IllegalArgumentException("unsupported cross op " + op));
    }

    private static Cron parse(Map<String, Object> params) {
        CronParser parser = new CronParser(definitionFor(params));
        return parser.parse(String.valueOf(params.get("expression"))).validate();
    }

    private static Cron parseTyped(String type, String expression) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("type", type);
        CronParser parser = new CronParser(definitionFor(params));
        return parser.parse(expression).validate();
    }

    private static CronDefinition definitionFor(Map<String, Object> params) {
        if (params.containsKey("definition")) {
            String name = String.valueOf(params.get("definition"));
            return switch (name) {
                case "CUSTOM_MIN_HOUR_DOW_OPTIONAL" -> CronDefinitionBuilder.defineCron()
                        .withMinutes().and()
                        .withHours().and()
                        .withDayOfWeek().optional().and()
                        .instance();
                case "CUSTOM_UNIX_DOM_DOW_AND" -> CronDefinitionBuilder.defineCron()
                        .withMinutes().withStrictRange().and()
                        .withHours().withStrictRange().and()
                        .withDayOfMonth().withStrictRange().and()
                        .withMonth().withStrictRange().and()
                        .withDayOfWeek().withValidRange(0, 7).withMondayDoWValue(1).withIntMapping(7, 0).withStrictRange().and()
                        .matchDayOfWeekAndDayOfMonth()
                        .instance();
                case "CUSTOM_MONTH_INTERVAL" -> CronDefinitionBuilder.defineCron()
                        .withMinutes().and()
                        .withHours().and()
                        .withDayOfWeek().supportsQuestionMark().and()
                        .withDayOfMonth().supportsL().supportsQuestionMark().and()
                        .withDayOfYear().supportsQuestionMark().and()
                        .withMonth().and()
                        .matchDayOfWeekAndDayOfMonth()
                        .withCronValidation(CronConstraintsFactory.ensureEitherDayOfWeekOrDayOfMonth())
                        .withCronValidation(CronConstraintsFactory.ensureEitherDayOfYearOrMonth())
                        .instance();
                case "CUSTOM_MONTH_INTERVAL_WITH_YEAR" -> CronDefinitionBuilder.defineCron()
                        .withMinutes().and()
                        .withHours().and()
                        .withDayOfWeek().withValidRange(1, 7).withMondayDoWValue(1).supportsQuestionMark().and()
                        .withDayOfMonth().supportsL().supportsQuestionMark().and()
                        .withDayOfYear().supportsQuestionMark().and()
                        .withMonth().and()
                        .withYear().optional().withValidRange(1970, 2099).and()
                        .matchDayOfWeekAndDayOfMonth()
                        .withCronValidation(CronConstraintsFactory.ensureEitherDayOfWeekOrDayOfMonth())
                        .withCronValidation(CronConstraintsFactory.ensureEitherDayOfYearOrMonth())
                        .instance();
                case "CUSTOM_DAY_OF_YEAR" -> CronDefinitionBuilder.defineCron()
                        .withSeconds().and()
                        .withMinutes().and()
                        .withHours().and()
                        .withDayOfMonth().withValidRange(1, 31).supportsL().supportsW().supportsLW().supportsQuestionMark().and()
                        .withMonth().and()
                        .withDayOfWeek().withValidRange(1, 7).withMondayDoWValue(2).supportsHash().supportsL().supportsQuestionMark().and()
                        .withYear().withValidRange(1900, 2099).optional().and()
                        .withDayOfYear().supportsQuestionMark().withValidRange(1, 366).optional().and()
                        .withCronValidation(CronConstraintsFactory.ensureEitherDayOfYearOrMonth())
                        .withCronValidation(CronConstraintsFactory.ensureEitherDayOfWeekOrDayOfMonth())
                        .instance();
                case "CUSTOM_YEAR_MONTH_DOM_HMS" -> CronDefinitionBuilder.defineCron()
                        .withYear().and()
                        .withMonth().and()
                        .withDayOfMonth().and()
                        .withHours().and()
                        .withMinutes().and()
                        .withSeconds().and()
                        .instance();
                case "CUSTOM_SECONDS_FIRST_LENIENT" -> CronDefinitionBuilder.defineCron()
                        .withSeconds().and()
                        .withMinutes().and()
                        .withHours().and()
                        .withDayOfMonth().withValidRange(1, 31).supportsL().supportsW().supportsLW().supportsQuestionMark().and()
                        .withMonth().and()
                        .withDayOfWeek().withValidRange(0, 7).withMondayDoWValue(1).withIntMapping(7, 0).supportsHash().supportsL().supportsQuestionMark().and()
                        .withYear().optional().withValidRange(1970, 2099).and()
                        .instance();
                case "CUSTOM_REBOOT" -> CronDefinitionBuilder.defineCron()
                        .withSupportedNicknameReboot()
                        .instance();
                default -> throw new IllegalArgumentException("unsupported definition " + name);
            };
        }
        return CronDefinitionBuilder.instanceDefinitionFor(CronType.valueOf(String.valueOf(params.getOrDefault("type", "QUARTZ"))));
    }

    private static CronMapper mapper(String name) {
        return switch (name) {
            case "fromCron4jToQuartz" -> CronMapper.fromCron4jToQuartz();
            case "fromQuartzToCron4j" -> CronMapper.fromQuartzToCron4j();
            case "fromQuartzToUnix" -> CronMapper.fromQuartzToUnix();
            case "fromUnixToQuartz" -> CronMapper.fromUnixToQuartz();
            case "fromQuartzToSpring" -> CronMapper.fromQuartzToSpring();
            case "fromSpringToQuartz" -> CronMapper.fromSpringToQuartz();
            default -> throw new IllegalArgumentException("unsupported mapper " + name);
        };
    }

    private static WeekDay weekday(String name) {
        return switch (name) {
            case "QUARTZ_WEEK_DAY" -> ConstantsMapper.QUARTZ_WEEK_DAY;
            case "JAVA8" -> ConstantsMapper.JAVA8;
            case "CRONTAB_WEEK_DAY" -> ConstantsMapper.CRONTAB_WEEK_DAY;
            default -> throw new IllegalArgumentException("unsupported weekday mapping " + name);
        };
    }

    private static ZonedDateTime zoned(String value) {
        return ZonedDateTime.parse(value);
    }

    private static Object optionalDate(Optional<ZonedDateTime> value) {
        return value.map(ZonedDateTime::toString).orElse(null);
    }

    private static Object optionalDuration(Optional<Duration> value) {
        return value.map(Duration::getSeconds).orElse(null);
    }

    private static Locale locale(String tag) {
        return Locale.forLanguageTag(tag.replace('_', '-'));
    }

    private static Map<String, Object> one(String key, Object value) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put(key, value);
        return out;
    }

    private static Map<String, Object> errorResult(Exception error) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("error", true);
        out.put("messageContains", String.valueOf(error.getMessage()));
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> getMap(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (value instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        return new LinkedHashMap<>();
    }

    private static boolean matches(Map<String, Object> expected, Map<String, Object> actual) {
        if (expected == null || actual == null) {
            return false;
        }
        for (Map.Entry<String, Object> entry : expected.entrySet()) {
            if (!actual.containsKey(entry.getKey())) {
                return false;
            }
            Object expectedValue = entry.getValue();
            Object actualValue = actual.get(entry.getKey());
            if ("messageContains".equals(entry.getKey())) {
                if (!String.valueOf(actualValue).contains(String.valueOf(expectedValue))) {
                    return false;
                }
            } else if (!canonical(expectedValue).equals(canonical(actualValue))) {
                return false;
            }
        }
        return true;
    }

    private static String canonical(Object value) {
        try {
            return JSON.writeValueAsString(sort(value));
        } catch (Exception error) {
            return String.valueOf(value);
        }
    }

    @SuppressWarnings("unchecked")
    private static Object sort(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            map.entrySet().stream()
                    .sorted(Comparator.comparing(e -> String.valueOf(e.getKey())))
                    .forEach(e -> out.put(String.valueOf(e.getKey()), sort(e.getValue())));
            return out;
        }
        if (value instanceof List<?> list) {
            return list.stream().map(CronUtilsReplay::sort).toList();
        }
        return value;
    }

    private static Map<String, Object> mutateExpected(Map<String, Object> expected) {
        Map<String, Object> out = new LinkedHashMap<>(expected);
        for (String key : List.of("error", "value")) {
            Object value = out.get(key);
            if (value instanceof Boolean bool) {
                out.put(key, !bool);
                return out;
            }
            if (value instanceof Number number) {
                out.put(key, number.longValue() + 1);
                return out;
            }
        }
        for (String key : List.of("string", "description", "instant", "messageContains")) {
            if (out.containsKey(key)) {
                out.put(key, String.valueOf(out.get(key)) + "__mutant__");
                return out;
            }
        }
        if (out.containsKey("dates") && out.get("dates") instanceof List<?> list) {
            List<Object> copy = new ArrayList<>(list);
            copy.add("__mutant__");
            out.put("dates", copy);
            return out;
        }
        if (out.containsKey("durationSeconds")) {
            Object value = out.get("durationSeconds");
            out.put("durationSeconds", value == null ? 1 : ((Number) value).longValue() + 1);
            return out;
        }
        out.put("__mutant__", true);
        return out;
    }
}
