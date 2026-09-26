#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'rubygems'

Gem.use_paths(File.expand_path('vendor', __dir__), [ File.expand_path('vendor', __dir__) ])

require 'fugit'

ENV['TZ'] ||= 'UTC'

module AverageAsRandom
  def self.rand(max)
    max / 2
  end
end

def read_payload(argv)
  path = argv.find { |a| a != '--fill' && a != '--mutant' }
  text = path ? File.read(path) : STDIN.read
  abort('missing JSON payload') if text.strip.empty?
  JSON.parse(text)
end

def parse_time(value)
  return value if value.is_a?(Time)
  return EtOrbi.make_time(value['local'], value['zone']) if value.is_a?(Hash) && value['local'] && value['zone']
  EtOrbi.make_time(value)
end

def fmt_time(time, with_rweek: false)
  t = EtOrbi.make_time(time)
  s = t.strftime('%Y-%m-%dT%H:%M:%S%:z %Z')
  with_rweek ? "#{s} rweek=#{t.rweek} rday=#{t.rday}" : s
end

def parse_opts(params)
  opts = {}
  case params['random']
  when false
    opts[:random] = false
  when 'average'
    opts[:random] = AverageAsRandom
  when true
    opts[:random] = true
  end
  opts[:multi] = params['multi'].to_sym if params['multi'].is_a?(String)
  opts
end

def with_zone(zone)
  old = ENV['TZ']
  ENV['TZ'] = zone if zone
  yield
ensure
  ENV['TZ'] = old
end

def parse_cron!(expression, params = {})
  cron = Fugit::Cron.parse(expression, parse_opts(params))
  raise ArgumentError, "unparseable cron #{expression.inspect}" unless cron
  cron
end

def run_contract(contract)
  params = contract['params'] || {}
  op = contract['op']

  with_zone(params['env_tz']) do
    case op
    when 'parse_cron'
      cron = Fugit::Cron.parse(params['expression'], parse_opts(params))
      return { 'value' => nil } unless cron
      {
        'class' => cron.class.to_s,
        'original' => cron.original,
        'cron' => cron.to_cron_s,
        'array' => cron.to_a,
        'hash' => cron.to_h.transform_keys(&:to_s),
        'zone' => cron.zone,
        'timezone' => cron.timezone && cron.timezone.name
      }
    when 'parse_cron_nil'
      { 'value' => Fugit::Cron.parse(params['expression'], parse_opts(params)).nil? }
    when 'do_parse_error'
      begin
        Fugit::Cron.do_parse(params['expression'], parse_opts(params))
        { 'error' => false, 'messageContains' => '' }
      rescue StandardError => e
        { 'error' => true, 'messageContains' => e.message }
      end
    when 'parse_kind'
      parsed = Fugit.parse(params['expression'], parse_opts(params))
      { 'class' => parsed && parsed.class.to_s, 'cron' => parsed.respond_to?(:to_cron_s) ? parsed.to_cron_s : nil }
    when 'parse_cronish'
      parsed = Fugit.parse_cronish(params['expression'], parse_opts(params))
      { 'class' => parsed && parsed.class.to_s, 'cron' => parsed.respond_to?(:to_cron_s) ? parsed.to_cron_s : nil }
    when 'determine_type'
      { 'type' => Fugit.determine_type(params['expression']) }
    when 'next_times'
      cron = parse_cron!(params['expression'], params)
      t = parse_time(params['start'])
      count = params.fetch('count', 1).to_i
      dates = count.times.map do
        t = cron.next_time(t)
        fmt_time(t, with_rweek: params['with_rweek'])
      end
      { 'dates' => dates }
    when 'previous_times'
      cron = parse_cron!(params['expression'], params)
      t = parse_time(params['start'])
      count = params.fetch('count', 1).to_i
      dates = count.times.map do
        t = cron.previous_time(t)
        fmt_time(t, with_rweek: params['with_rweek'])
      end
      { 'dates' => dates }
    when 'next_iterator'
      cron = parse_cron!(params['expression'], params)
      dates = cron.next(params['start']).take(params.fetch('count', 1).to_i)
      { 'dates' => dates.map { |t| fmt_time(t, with_rweek: params['with_rweek']) } }
    when 'prev_iterator'
      cron = parse_cron!(params['expression'], params)
      dates = cron.prev(parse_time(params['start'])).take(params.fetch('count', 1).to_i)
      { 'dates' => dates.map { |t| fmt_time(t, with_rweek: params['with_rweek']) } }
    when 'within'
      cron = parse_cron!(params['expression'], params)
      dates =
        if params['range']
          cron.within(parse_time(params['start'])..parse_time(params['end']))
        else
          cron.within(parse_time(params['start']), params['end'])
        end
      { 'dates' => dates.map { |t| fmt_time(t, with_rweek: params['with_rweek']) } }
    when 'match'
      cron = parse_cron!(params['expression'], params)
      { 'value' => cron.match?(params['date']) }
    when 'rough_frequency'
      cron = parse_cron!(params['expression'], params)
      { 'seconds' => cron.rough_frequency }
    when 'brute_frequency'
      cron = parse_cron!(params['expression'], params)
      f = cron.brute_frequency(params.fetch('year', 2017).to_i)
      {
        'debug' => f.to_debug_s,
        'occurrences' => f.occurrences,
        'span_years' => f.span_years.to_i,
        'yearly_occurrences' => f.yearly_occurrences.to_i
      }
    when 'seconds'
      cron = parse_cron!(params['expression'], params)
      { 'seconds' => cron.seconds }
    when 'equality'
      left = Fugit::Cron.parse(params['left'], parse_opts(params))
      right = Fugit::Cron.parse(params['right'], parse_opts(params))
      { 'value' => left == right, 'left' => left && left.to_cron_s, 'right' => right && right.to_cron_s }
    when 'rweek_ref_sequence'
      old = EtOrbi.rweek_ref
      begin
        EtOrbi.rweek_ref = params['ref'].to_sym
        cron = parse_cron!(params['expression'], params)
        dates = cron.next(params['start']).take(params.fetch('count', 1).to_i)
        { 'ref' => EtOrbi.rweek_ref, 'dates' => dates.map { |t| "#{t.strftime('%F %a')} #{t.rweek}" } }
      ensure
        EtOrbi.rweek_ref = old if old
      end
    else
      { 'error' => true, 'messageContains' => "unsupported op #{op}" }
    end
  end
rescue StandardError => e
  { 'error' => true, 'messageContains' => e.message }
end

def canonical(value)
  case value
  when Hash
    value.keys.sort.each_with_object({}) { |k, h| h[k] = canonical(value[k]) }
  when Array
    value.map { |v| canonical(v) }
  else
    value
  end
end

def mutate_value(value)
  case value
  when true then false
  when false then true
  when Integer then value + 1
  when Float then value + 1.0
  when String
    value.match?(/\d/) ? value.sub(/\d+/) { |m| (m.to_i + 1).to_s } : "#{value}__mutant"
  when Array
    value.empty? ? [ '__mutant' ] : [ mutate_value(value.first), *value[1..] ]
  when Hash
    return { '__mutant' => true } if value.empty?
    key = value.keys.first
    value.merge(key => mutate_value(value[key]))
  when NilClass
    '__mutant'
  else
    '__mutant'
  end
end

def equal?(a, b)
  JSON.generate(canonical(a)) == JSON.generate(canonical(b))
end

payload = read_payload(ARGV)
fill = ARGV.include?('--fill')
mutant = ARGV.include?('--mutant')
list = payload.is_a?(Array)
contracts = list ? payload : [ payload ]

if fill
  filled = contracts.map { |c| c.merge('expected' => run_contract(c)) }
  puts JSON.generate(list ? filled : filled.first)
  exit 0
end

results = contracts.map do |c|
  actual = run_contract(c)
  expected = c['expected']
  expected = mutate_value(expected) if mutant
  { 'name' => c['name'], 'ok' => mutant ? !equal?(actual, expected) : equal?(actual, expected), 'actual' => actual, 'expected' => expected }
end

passed = results.count { |r| r['ok'] }
puts JSON.generate({ 'ok' => passed == contracts.length, 'passed' => passed, 'total' => contracts.length, 'mode' => mutant ? 'mutant' : 'replay', 'results' => results })
exit(passed == contracts.length ? 0 : 1)
