# frozen_string_literal: true

# This process's own copies of the short-lived markers the additional-issuer helpers write to the
# cache: the backoff after a failed fetch, and the refetch slot for an unknown key id. A copy holds
# when the cache keeps nothing -- a null store, or Redis while it is unreachable -- so each limit
# still applies within the process, and threads waiting on a fetch that failed share its answer.
module TokenValidator::ProcessMarkerHelper
  # Guards the markers, which every thread in the process shares.
  PROCESS_MARKERS_GUARD = Mutex.new

  private

  def marked_in_process?(marker)
    PROCESS_MARKERS_GUARD.synchronize { process_marker_live?(marker) }
  end

  def mark_in_process(marker, duration)
    PROCESS_MARKERS_GUARD.synchronize { process_markers[marker] = Time.now + duration }
  end

  # Sets +marker+ for +duration+ unless it is set already, and answers whether it did.
  def mark_in_process_unless_marked(marker, duration)
    PROCESS_MARKERS_GUARD.synchronize do
      next false if process_marker_live?(marker)

      process_markers[marker] = Time.now + duration
      true
    end
  end

  def forget_process_markers
    PROCESS_MARKERS_GUARD.synchronize { process_markers.clear }
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
end
