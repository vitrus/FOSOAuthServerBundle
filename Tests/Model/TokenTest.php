<?php

declare(strict_types=1);

/*
 * This file is part of the FOSOAuthServerBundle package.
 *
 * (c) FriendsOfSymfony <http://friendsofsymfony.github.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\OAuthServerBundle\Tests\Model;

use FOS\OAuthServerBundle\Model\Token;
use FOS\OAuthServerBundle\Tests\TestCase;

/**
 * @group time-sensitive
 */
class TokenTest extends TestCase
{
    /**
     * @dataProvider getTestHasExpiredData
     *
     * @param mixed $expiresAt
     * @param mixed $expect
     */
    public function testHasExpired($expiresAt, $expect): void
    {
        $token = new Token();
        $token->setExpiresAt($expiresAt);

        $this->assertSame($expect, $token->hasExpired());
    }

    public static function getTestHasExpiredData(): array
    {
        return [
            [time() + 60, false],
            [time() - 60, true],
            [null, false],
        ];
    }

    public function testExpiresIn(): void
    {
        $token = new Token();

        $this->assertSame(PHP_INT_MAX, $token->getExpiresIn());
    }

    public function testExpiresInWithExpiresAt(): void
    {
        $token = new Token();
        $token->setExpiresAt(time() + 60);

        $this->assertSame(60, $token->getExpiresIn());
    }
}
