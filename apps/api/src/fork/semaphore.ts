import { ForkError } from "./errors";

type Waiter = {
  resolve: () => void;
  reject: (err: Error) => void;
  timer?: NodeJS.Timeout;
};

export class Semaphore {
  private available: number;
  private readonly waiters: Waiter[] = [];

  constructor(size: number) {
    if (size < 1) {
      throw new Error("Semaphore size must be at least 1");
    }
    this.available = size;
  }

  async acquire(deadlineMs: number): Promise<void> {
    if (this.available > 0) {
      this.available -= 1;
      return;
    }

    if (Date.now() > deadlineMs) {
      throw new ForkError(
        "QUEUE_TIMEOUT",
        "timed out waiting for a scrape slot",
      );
    }

    return new Promise<void>((resolve, reject) => {
      const waiter: Waiter = {
        resolve: () => {
          if (waiter.timer) {
            clearTimeout(waiter.timer);
          }
          resolve();
        },
        reject: (err: Error) => {
          if (waiter.timer) {
            clearTimeout(waiter.timer);
          }
          reject(err);
        },
      };

      const msLeft = deadlineMs - Date.now();
      if (msLeft <= 0) {
        reject(
          new ForkError(
            "QUEUE_TIMEOUT",
            "timed out waiting for a scrape slot",
          ),
        );
        return;
      }

      waiter.timer = setTimeout(() => {
        const idx = this.waiters.indexOf(waiter);
        if (idx !== -1) {
          this.waiters.splice(idx, 1);
        }
        waiter.reject(
          new ForkError(
            "QUEUE_TIMEOUT",
            "timed out waiting for a scrape slot",
          ),
        );
      }, msLeft);

      this.waiters.push(waiter);
    });
  }

  release(): void {
    const next = this.waiters.shift();
    if (next) {
      // Hand the slot directly to the next waiter (available stays the same).
      next.resolve();
      return;
    }
    this.available += 1;
  }
}
