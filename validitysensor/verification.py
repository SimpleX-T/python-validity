from .sensor import FingerNotMatchedException


def identify_with_retries(identify, update_cb, retry_cb, max_attempts=3):
    """Retry only clean on-chip no-template results, up to a fixed limit."""
    if max_attempts < 1:
        raise ValueError('max_attempts must be at least one')

    for attempt in range(1, max_attempts + 1):
        try:
            return identify(update_cb)
        except FingerNotMatchedException:
            if attempt == max_attempts:
                raise
            retry_cb(attempt, max_attempts)
