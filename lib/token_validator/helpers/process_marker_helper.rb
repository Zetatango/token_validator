# frozen_string_literal: true

require 'active_support/cache'

# This process's own copies of what the additional-issuer helpers keep in the cache: the short-lived
# markers (the backoff after a failed fetch, the refetch slot for an unknown key id, and when a key
# set was last fetched), and the last machine token and key set each fetch produced. A copy holds
# when the cache keeps nothing -- a null store, or Redis while it is unreachable -- so each limit
# still applies within the process, and threads waiting on a fetch share its answer, whether it
# failed or succeeded.
module TokenValidator::ProcessMarkerHelper
  # Guards the markers and copies, which every thread in the process shares.
  PROCESS_MARKERS_GUARD = Mutex.new

  private

  def marked_in_process?(marker)
    PROCESS_MARKERS_GUARD.synchronize { process_marker_live?(marker) }
  end

  def mark_in_process(marker, duration)
    PROCESS_MARKERS_GUARD.synchronize { process_markers[marker] = Time.now + duration }
  end

  # Keeps this process's copy of +value+ under +key+ for +duration+.
  def keep_in_process(key, value, duration)
    process_copies.write(key, value, expires_in: duration)
  end

  # This process's copy under +key+, or nil once it has expired or was never kept.
  def kept_in_process(key)
    process_copies.read(key)
  end

  def forget_process_markers
    PROCESS_MARKERS_GUARD.synchronize { process_markers.clear }
    process_copies.clear
  end

  # Called with PROCESS_MARKERS_GUARD held.
  def process_marker_live?(marker)
    ends_at = process_markers[marker]
    !ends_at.nil? && Time.now < ends_at
  end

  # When each of this process's markers ends, by the cache key of the marker it copies.
  def process_markers
    @process_markers ||= {}
  end

  # An in-memory store, so each copy expires on its own and every reader gets its own duplicate, as
  # it would from the cache.
  def process_copies
    PROCESS_MARKERS_GUARD.synchronize { @process_copies ||= ActiveSupport::Cache::MemoryStore.new }
  end
end
