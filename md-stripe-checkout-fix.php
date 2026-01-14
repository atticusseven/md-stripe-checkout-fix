<?php
/**
 * Plugin Name: MemberDash Stripe Checkout Assign (MU)
 * Description: Workaround: assign MemberDash membership on Stripe checkout.session.completed
 * Author: Ben Neale
 *
 * Add to wp-config.php (recommended):
 * define('MD_STRIPE_WEBHOOK_SECRET', 'whsec_...');
 */

add_action('init', function () {

    // Only run on the MemberDash Stripe webhook endpoint.
    if (!isset($_GET['memberdash-integration']) || $_GET['memberdash-integration'] !== 'stripe') {
        return;
    }

    // Stripe webhooks are POST requests.
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        return;
    }

    $payload = file_get_contents('php://input');
    if (!$payload) {
        return;
    }

    $event = json_decode($payload, true);
    if (!is_array($event) || empty($event['type'])) {
        return;
    }

    // Only handle checkout.session.completed (MemberDash ignores this for recurring in some setups).
    if ($event['type'] !== 'checkout.session.completed') {
        return; // Let MemberDash handle/ignore other events as usual.
    }

    // Optional: verify Stripe signature.
    if (defined('MD_STRIPE_WEBHOOK_SECRET') && MD_STRIPE_WEBHOOK_SECRET) {
        $sig = $_SERVER['HTTP_STRIPE_SIGNATURE'] ?? '';
        if (!$sig || !md_stripe_verify_signature($payload, $sig, MD_STRIPE_WEBHOOK_SECRET)) {
            status_header(400);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['success' => false, 'data' => ['message' => 'Invalid Stripe signature']]);
            exit;
        }
    }

    $obj  = $event['data']['object'] ?? [];
    $meta = $obj['metadata'] ?? [];

    // Only act on Checkout Sessions created by MemberDash.
    if (($meta['is_memberdash'] ?? '') !== 'true') {
        status_header(200);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['success' => true, 'data' => ['message' => 'Not a MemberDash session; ignored']]);
        exit;
    }

    $user_id       = isset($meta['member_id']) ? (int) $meta['member_id'] : 0;
    $membership_id = isset($meta['membership_id']) ? (int) $meta['membership_id'] : 0;

    if (!$user_id || !$membership_id) {
        status_header(200);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['success' => true, 'data' => ['message' => 'Missing member_id or membership_id; ignored']]);
        exit;
    }

    // Ensure MemberDash/Membership2 is loaded.
    if (!class_exists('MS_Factory') || !class_exists('MS_Model_Relationship')) {
        status_header(200);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['success' => true, 'data' => ['message' => 'MemberDash classes not available; ignored']]);
        exit;
    }

    // If the user already has this membership, do nothing (prevents duplicates).
    if (class_exists('MS_Factory')) {
        $member = MS_Factory::load('MS_Model_Member', $user_id);

        // Different MemberDash builds expose different methods, so we try a couple.
        if ($member) {
            if (method_exists($member, 'has_membership') && $member->has_membership($membership_id)) {
                status_header(200);
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode(['success' => true, 'data' => ['message' => 'User already has membership; ignored']]);
                exit;
            }

            if (method_exists($member, 'get_membership_ids')) {
                $ids = (array) $member->get_membership_ids();
                if (in_array($membership_id, $ids, true)) {
                    status_header(200);
                    header('Content-Type: application/json; charset=utf-8');
                    echo json_encode(['success' => true, 'data' => ['message' => 'User already has membership; ignored']]);
                    exit;
                }
            }
        }
    }



    // Create a relationship (membership assignment). This avoids calling controller methods that may be private.
    try {
        $rel = MS_Factory::create('MS_Model_Relationship');

        // Core relationship fields.
        $rel->user_id       = $user_id;
        $rel->membership_id = $membership_id;

        // Start now, set active where possible.
        if (property_exists($rel, 'start_date')) {
            $rel->start_date = current_time('mysql');
        }

        // Prefer constants if available.
        if (defined('MS_Model_Relationship::STATUS_ACTIVE')) {
            $rel->status = MS_Model_Relationship::STATUS_ACTIVE;
        } else {
            $rel->status = 'active';
        }

        // Persist.
        if (method_exists($rel, 'save')) {
            $rel->save();
        }

        status_header(200);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'success' => true,
            'data' => [
                'message' => 'Membership relationship created on checkout.session.completed',
                'user_id' => $user_id,
                'membership_id' => $membership_id,
            ],
        ]);
        exit;

    } catch (\Throwable $e) {
        // Log for debugging; still return 200 to Stripe.
        error_log('[MD Stripe Assign] Exception: ' . $e->getMessage());

        status_header(200);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['success' => true, 'data' => ['message' => 'Exception occurred; check debug.log']]);
        exit;
    }

}, 0);

/**
 * Verify Stripe webhook signature (v1).
 * Minimal implementation: accepts a single v1 signature.
 */
function md_stripe_verify_signature(string $payload, string $sig_header, string $secret): bool {
    $timestamp = null;
    $signature = null;

    foreach (explode(',', $sig_header) as $part) {
        $part = trim($part);
        if (strpos($part, 't=') === 0) {
            $timestamp = substr($part, 2);
        } elseif (strpos($part, 'v1=') === 0) {
            $signature = substr($part, 3);
        }
    }

    if (!$timestamp || !$signature) {
        return false;
    }

    $signed_payload = $timestamp . '.' . $payload;
    $expected = hash_hmac('sha256', $signed_payload, $secret);

    return hash_equals($expected, $signature);
}