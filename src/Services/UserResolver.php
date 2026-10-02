<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Log;
use Ratespecial\Logto\Contracts\OAuthScopable;
use Ratespecial\Logto\Events\UserProvisionedEvent;
use Ratespecial\Logto\Exceptions\DuplicateUserEmailException;
use RuntimeException;
use Throwable;

/**
 * Turns validated Logto claims into a host-app user for the API guard.
 *
 * - Looks the user up by `logto.subject-column`, optionally claiming an unclaimed user by email.
 * - Persists claim-mapped attributes and dispatches {@see UserProvisionedEvent} for new rows.
 * - Throws {@see DuplicateUserEmailException} when saving collides with another row's email on a unique index.
 */
class UserResolver
{
    /**
     * @param  class-string<Authenticatable>  $userModel
     * @param  array<string, string>  $modelAttributes  Mapping of JWT claim name => user model attribute name.
     */
    public function __construct(
        private readonly string $userModel,
        private readonly array $modelAttributes = [],
    ) {}

    /**
     * Build a resolver for the model behind an `auth.providers.*` entry.
     */
    public static function forProvider(string $provider): self
    {
        $model = config("auth.providers.{$provider}.model");

        if (! is_string($model) || $model === '') {
            throw new RuntimeException("Auth provider [{$provider}] has no model configured");
        }

        return new self($model, config('logto.model-attributes', []));
    }

    /**
     * @param  array<string, mixed>  $claims  Must contain a non-empty `sub`.
     *
     * @throws DuplicateUserEmailException
     */
    public function resolve(array $claims): Authenticatable
    {
        $subjectColumn = config('logto.subject-column');

        /** @var Model $model */
        $model = new $this->userModel();

        /** @var Authenticatable&Model $user */
        $user = $model->newQuery()
            ->firstOrNew([$subjectColumn => $claims['sub']]);

        if (! $user->exists && config('logto.link-unclaimed-by-email')) {
            $user = $this->findUnclaimedUser($model, $subjectColumn, $claims) ?? $user;
        }

        // forceFill so claim-mapped attributes are written even when the host
        // app's user model doesn't mark them fillable. The values come from a
        // validated token, not request input, so mass-assignment guarding is moot.
        $attributes                 = $this->mapClaimsToAttributes($claims);
        $attributes[$subjectColumn] = $claims['sub'];

        $user->forceFill($attributes);

        $this->save($user, $subjectColumn, $claims);

        $this->withScopes($user, $claims);

        if ($user->wasRecentlyCreated) {
            UserProvisionedEvent::dispatch($user);
        }

        return $user;
    }

    /**
     * @param  array<string, mixed>  $claims
     *
     * @throws DuplicateUserEmailException
     */
    protected function save(Model $user, string $subjectColumn, array $claims): void
    {
        try {
            $user->save();
        } catch (UniqueConstraintViolationException $ex) {
            throw $this->findEmailConflict($user, $subjectColumn, $claims, $ex) ?? $ex;
        }
    }

    /**
     * Determine whether a unique violation was caused by another row already holding the token's email.
     *
     * @param  array<string, mixed>  $claims
     */
    protected function findEmailConflict(
        Model $user,
        string $subjectColumn,
        array $claims,
        Throwable $previous,
    ): ?DuplicateUserEmailException {
        $emailColumn = $this->modelAttributes['email'] ?? null;
        if ($emailColumn === null || empty($claims['email'])) {
            return null;
        }

        $existing = $user->newQuery()
            ->where($emailColumn, $claims['email'])
            ->when($user->exists, fn ($query) => $query->whereKeyNot($user->getKey()))
            ->first();

        if ($existing === null) {
            return null;
        }

        return new DuplicateUserEmailException(
            subject: (string) $claims['sub'],
            email: (string) $claims['email'],
            existingUserKey: $existing->getKey(),
            existingUserUnclaimed: $existing->getAttribute($subjectColumn) === null,
            previous: $previous,
        );
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    protected function withScopes(Authenticatable $user, array $claims): Authenticatable
    {
        if ($user instanceof OAuthScopable) {
            $user->setOAuthScopes((string) ($claims['scope'] ?? ''));
        }

        return $user;
    }

    /**
     * Find an existing user whose subject was cleared (e.g. after a Logto tenant migration)
     * and whose email matches the token's email claim, so it can be claimed by the new subject.
     *
     * @param  array<string, mixed>  $claims
     * @return (Authenticatable&Model)|null
     */
    protected function findUnclaimedUser(Model $model, string $subjectColumn, array $claims): ?Model
    {
        $emailColumn = $this->modelAttributes['email'] ?? null;
        if ($emailColumn === null || empty($claims['email'])) {
            return null;
        }

        /** @var (Authenticatable&Model)|null $user */
        $user = $model->newQuery()
            ->whereNull($subjectColumn)
            ->where($emailColumn, $claims['email'])
            ->first();

        if ($user !== null) {
            Log::info("Logto linked unclaimed user {$user->getKey()} to subject {$claims['sub']}");
        }

        return $user;
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return array<string, mixed>
     */
    protected function mapClaimsToAttributes(array $claims): array
    {
        $attributes = [];
        foreach ($this->modelAttributes as $claim => $field) {
            if (! empty($claims[$claim])) {
                $attributes[$field] = $claims[$claim];
            }
        }

        return $attributes;
    }
}
